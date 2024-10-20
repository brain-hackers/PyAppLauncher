#include <string.h>
#include <wchar.h>
#include <windows.h>

#define CP_UTF8 65001

// searchPath + "\\python(X.Y)\\pythonX.Y(.Z).exe"

const wchar_t *searchPathes[] = {L"\\Storage Card", L"\\NAND3", L".", NULL};

struct PythonVersion
{
    int major;
    int minor;
    int micro;
    char release[3]; // a, b, rc, +
    int serial;
    int significantDigits;
};

struct PythonVersionCondition
{
    unsigned int mode;
    PythonVersion *version;
};

#define PY_VER_ARBITRARY 0  // no-prefix
#define PY_VER_COMPATIBLE 1 // ~=
#define PY_VER_SMALLER 2    // <
#define PY_VER_SMALLER_EQ 3 // <=
#define PY_VER_BIGGER 4     // >
#define PY_VER_BIGGER_EQ 5  // >=

struct PyAppData
{
    wchar_t curPath[MAX_PATH + 1];
    wchar_t pythonPath[MAX_PATH + 1];
    char *args;
    PythonVersionCondition *pyVersions[127];
    int pyVersionCount;
    wchar_t *environs[127];
    int environCount;
};

PyAppData config = {0};

#define PATHCCH_NONE 0
#define PATHCCH_ALLOW_LONG_PATHS 1

#define PATHCCH_E_FILENAME_TOO_LONG ((HRESULT)0x8000FFFFL) /* FIXME: could not find its actual value */

HRESULT
PathCchCanonicalizeEx(wchar_t *pszPathOut, size_t cchPathOut, wchar_t *pszPathIn, unsigned long dwFlags)
{
    /* read handed path from the end to the begining so we can make the result without going back */
    if (!dwFlags & PATHCCH_ALLOW_LONG_PATHS && cchPathOut > MAX_PATH + 1)
        return E_INVALIDARG;

    int isCur = 0;
    int isPar = 0;
    int ignores = 0;
    HRESULT result = S_OK;

    wchar_t *resPath = (wchar_t *)calloc(cchPathOut, sizeof(wchar_t));
    wchar_t *tmpPath = (wchar_t *)calloc(cchPathOut, sizeof(wchar_t));

    size_t length = 0;
    size_t lenTmp = 0;

    int index;

    if (pszPathIn == NULL)
    {
        wmemcpy(pszPathOut, L"\0", 1);
        goto done;
    }

    index = wcslen(pszPathIn) - 1;
    if (index < 0)
    {
        wmemcpy(pszPathOut, L"\0", 1);
        goto done;
    }

    while (index >= 0)
    {
        wcsncpy(tmpPath + (lenTmp + isCur + isPar), pszPathIn + index, 1);
        if ((*(pszPathIn + index) == L'\\' || *(pszPathIn + index) == L'/'))
        {
            if (isPar)
                ignores++;
            if (!isCur && !ignores)
            {
                wcsncpy(resPath + length, L"\\", 1);
                length++;
            }
            if (!isCur && ignores)
            {
                ignores--;
            }
            lenTmp = 0;
            isCur = 0;
            isPar = 0;
            index--;
            continue;
        }
        if (!lenTmp && !isPar && *(pszPathIn + index) == L'.')
        {
            if (!isCur)
                isCur = 1;
            else
                isPar = 1;
        }
        else if (isCur && (isPar || *(pszPathIn + index) == L'.'))
        {
            if (isPar)
            {
                wcsncpy(resPath + length, L"..", 2);
                length++;
                isCur = 0;
                isPar = 0;
                lenTmp = 2;
            }
            else
            {
                wcsncpy(resPath + length, L".", 1);
                isCur = 0;
                lenTmp = 1;
            }
        }
        if (!(isCur || ignores))
        {
            wcsncpy(resPath + length, pszPathIn + index, 1);
            length++;
            lenTmp++;
        }
        index--;
    }
    if (ignores && *resPath == L'\0' && *tmpPath == L'\0')
    {
        wmemcpy(resPath, tmpPath, wcslen(tmpPath));
        length = lenTmp + isCur + isPar;
    }

    if (!dwFlags & PATHCCH_ALLOW_LONG_PATHS && length > MAX_PATH)
    {
        result = PATHCCH_E_FILENAME_TOO_LONG;
        goto done;
    }

    index++;
    while (index < length)
    {
        *(pszPathOut + index) = *(resPath + (length - index - 1));
        index++;
    }

    *(pszPathOut + length) = L'\0';

    goto done;
done:
    free(tmpPath);
    free(resPath);
    return result;
}

int GetPyVersion(char *verstr, PythonVersion *pyver)
{
    if (pyver == NULL)
    {
        return 0;
    }
    if (verstr == NULL)
    {
        *pyver = {0, 0, 0, {0, 0, 0}, 0, 0};
        return 1;
    }

    char *s;
    char *t;
    char tmp[256];
    if (strlen(verstr) >= 256)
    {
        return 0;
    }

    pyver->release[0] = '\0';

    strcpy(tmp, verstr);

    s = tmp;
    t = tmp;
    pyver->significantDigits = 1;
    s += strspn(s, "0123456789");
    if (*s == '.' && s != t)
    {
        *s = '\0';
        pyver->major = atoi(t);
        s++;
    }
    else if (*s == '\0' && s != t)
    {
        pyver->major = atoi(t);
        pyver->significantDigits = 1;
        return 1;
    }
    else
        return 0;

    t = s;
    pyver->significantDigits = 2;
    s += strspn(s, "0123456789");
    if (*s == '.' && s != t)
    {
        *s = '\0';
        pyver->minor = atoi(t);
        s++;
    }
    else if (*s == '\0' && s != t)
    {
        pyver->minor = atoi(t);
        return 1;
    }
    else if (*s == '*' && s - 1 == t && *(s + 1) == '\0')
    {
        pyver->minor = -1;
        return 1;
    }
    else
    {
        return 0;
    }

    t = s;
    pyver->significantDigits = 3;
    s += strspn(s, "0123456789");

    if (s == t)
        return 0;

    char *u, *v;
    u = s;
    if (*s == 'a')
    {
        strcpy(pyver->release, "a");
        u++;
    }
    else if (*s == 'b')
    {
        strcpy(pyver->release, "b");
        u++;
    }
    else if (*s == 'r' && *(s + 1) == 'c')
    {
        strcpy(pyver->release, "rc");
        u += 2;
    }
    else if (*s == '\0' || *s == '+')
    {
        return 1;
    }
    else
    {
        return 0;
    }

    *s = '\0';
    pyver->micro = atoi(t);

    if (s != u)
    {
        t = u;
        s = t + strspn(t, "0123456789");
        if (*s == '+')
            *s = '\0';

        if (*s != '\0')
            return 0;

        pyver->serial = atoi(t);
    }

    return 1;
}

int LoadConfig(PyAppData *config)
{
    char *c, *d, *e;
    static wchar_t *wtext;
    char *text;
    long unsigned int textlen;
    wchar_t filename[MAX_PATH + 1];

    char newline[3] = "\r\n";

    config->environCount = 0;

    HANDLE hFile;

    wcscpy(filename, config->curPath);
    wcscat(filename, L"\\config.ini");

    hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (GetLastError() != ERROR_ALREADY_EXISTS)
    {
        strcpy(text, "");

        textlen = 0;

        long unsigned int written = 0;
        if (!WriteFile(hFile, text, textlen, &written, NULL))
        {
            CloseHandle(hFile);
            return -1;
        }
    }
    else
    {
        DWORD filesize;
        filesize = GetFileSize(hFile, NULL);
        if (filesize == 0xffffffff)
        {
            CloseHandle(hFile);
            return -1;
        }
        text = (char *)calloc(filesize + 1, sizeof(char));
        if (text == NULL || !ReadFile(hFile, text, filesize, &textlen, NULL))
        {
            free(text);
            CloseHandle(hFile);
            return -1;
        }
    }
    CloseHandle(hFile);

    c = text;

    if (strstr(text, newline) == NULL)
    {
        strcpy(newline, "\n");
    }

    // BOM
    if (!strncmp(c, "\xEF\xBB\xBF", 3))
    {
        c += 3;
    }

    char keystr[65];
    char valstr[MAX_PATH + 1];

    while (c != NULL && *c != '\0')
    {
        d = c;
        c = strstr(c, newline);
        if (c != NULL)
        {
            *c = '\0';
        }
        if (*d != ';' && strlen(d) > 0)
        {
            if (strchr(d, '=') == NULL)
                goto error;

            e = keystr;
            while (*d != ' ' && *d != '=')
            {
                *e = *d;
                d++;
                e++;
            }
            if (strspn(d, "= ") <= strcspn(d, "="))
                goto error;

            *e = '\0';
            d += strspn(d, "= ");
            strcpy(valstr, d);

            // handle

            if (!strcmp(keystr, "python"))
            {
                if (*(config->pythonPath) != L'\0')
                    goto error;
                MultiByteToWideChar(CP_UTF8, 0, valstr, -1, config->pythonPath, MAX_PATH + 1);
            }
            else if (!strcmp(keystr, "args"))
            {
                if (config->args != NULL)
                    goto error;
                config->args = (char *)calloc(strlen(valstr) + 1, sizeof(char));
                if (config->args == NULL)
                    goto error;
                strcpy(config->args, valstr);
            }
            else if (!strcmp(keystr, "version"))
            {
                if (config->pyVersions[0] != NULL)
                    goto error;
                char *s;
                s = valstr;
                while (strlen(s) > 0)
                {
                    PythonVersionCondition cond = {0};
                    PythonVersion pyver = {0};

                    if (strcspn(s, "0123456789") == 0)
                    {
                        // arbitrary equality
                        cond.mode = PY_VER_ARBITRARY;
                    }
                    else if (strspn(s, "<>=~") == 1)
                    {
                        // exclusive ordered comparison
                        if (strspn(s, "<>") == 0)
                        {
                            goto error;
                        }
                        if (*s == '<')
                        {
                            cond.mode = PY_VER_SMALLER;
                        }
                        else if (*s == '>')
                        {
                            cond.mode = PY_VER_BIGGER;
                        }
                        else
                        {
                            goto error;
                        }
                    }
                    else if (strspn(s, "<>=~") == 2)
                    {
                        if (*(s + 1) != '=')
                        {
                            goto error;
                        }
                        if (*s == '~')
                        {
                            cond.mode = PY_VER_COMPATIBLE;
                        }
                        else if (*s == '<')
                        {
                            cond.mode = PY_VER_SMALLER_EQ;
                        }
                        else if (*s == '>')
                        {
                            cond.mode = PY_VER_BIGGER_EQ;
                        }
                        else
                        {
                            goto error;
                        }
                    }
                    else
                    {
                        goto error;
                    }
                    s += strspn(s, "<>=~ ");

                    size_t verlen = strcspn(s, ", ");
                    char *verstr = (char *)calloc(verlen + 1, sizeof(char));
                    if (verstr == NULL)
                        goto error;
                    strncpy(verstr, s, verlen);
                    s += verlen;
                    s += strspn(s, ", ");

                    if (!GetPyVersion(verstr, &pyver))
                    {
                        free(verstr);
                        goto error;
                    }
                    free(verstr);

                    if (config->pyVersionCount == 127)
                    {
                        goto error;
                    }

                    PythonVersionCondition *cond2;

                    cond.version = (PythonVersion *)calloc(1, sizeof(PythonVersion));
                    if (cond.version == NULL)
                    {
                        goto error;
                    }
                    memcpy(cond.version, &pyver, sizeof(PythonVersion));

                    cond2 = (PythonVersionCondition *)calloc(1, sizeof(PythonVersionCondition));
                    if (cond2 == NULL)
                    {
                        free(cond.version);
                        goto error;
                    }

                    memcpy(cond2, &cond, sizeof(PythonVersionCondition));
                    config->pyVersions[config->pyVersionCount] = cond2;
                    config->pyVersionCount++;
                }
            }
            else if (!strcmp(keystr, "environ_file"))
            {
                if (config->environCount > 0)
                {
                    goto error;
                }
                wchar_t *s;
                int wlen = MultiByteToWideChar(CP_UTF8, 0, valstr, -1, NULL, 0);
                s = (wchar_t *)calloc(wlen, sizeof(wchar_t));
                MultiByteToWideChar(CP_UTF8, 0, valstr, -1, s, wlen);
                config->environs[0] = s;
                config->environCount = -1;
            }
            else if (!strncmp(keystr, "environ_file_", 13))
            {
                if (config->environCount >= 0 && atoi(keystr + 13) == config->environCount + 1)
                {
                    if (config->environCount == 127)
                    {
                        goto error;
                    }
                    wchar_t *s;
                    int wlen = MultiByteToWideChar(CP_UTF8, 0, valstr, -1, NULL, 0);
                    s = (wchar_t *)calloc(wlen, sizeof(wchar_t));
                    MultiByteToWideChar(CP_UTF8, 0, valstr, -1, s, wlen);
                    config->environs[config->environCount] = s;
                    config->environCount++;
                }
                else
                {
                    goto error;
                }
            }
            else
            {
                OutputDebugStringW(L"unknown key, skipping...");
            }
        }
        if (c == NULL)
            break;
        if (*(c + 1) == '\n')
        {
            c++;
        }
        c++;
    }
    free(text);
    return 0;
error:
    free(text);
    return -1;
}

int checkPythonVersion(PythonVersion *pyver, PythonVersionCondition *cond)
{
    int result = 1;
    int eq = cond->mode == PY_VER_ARBITRARY || cond->mode == PY_VER_COMPATIBLE || cond->mode == PY_VER_BIGGER_EQ ||
             cond->mode == PY_VER_SMALLER_EQ;

    if (cond->mode == PY_VER_BIGGER || cond->mode == PY_VER_BIGGER_EQ || cond->mode == PY_VER_COMPATIBLE)
    {
        if (pyver->major < cond->version->major)
            result = 0;
        else if (pyver->major == cond->version->major)
        {
            if (cond->version->significantDigits == 1 && !eq)
                result = 0;
            else if (cond->version->significantDigits > 1 && pyver->minor < cond->version->minor)
                result = 0;
            else if (pyver->minor == cond->version->minor)
            {
                if (cond->version->significantDigits == 2 && !eq)
                    result = 0;
                else if (cond->version->significantDigits > 2 && pyver->micro < cond->version->micro)
                    result = 0;
                else if (cond->version->significantDigits >= 3 && pyver->micro == cond->version->micro)
                {
                    int release;
                    if (pyver->release[0] == 'a')
                        release = 0;
                    else if (pyver->release[0] == 'b')
                        release = 1;
                    else if (pyver->release[0] == 'r')
                        release = 2;
                    else
                        release = 3;

                    if ((cond->version->release[0] == 'a' && release == 0 && !eq) ||
                        (cond->version->release[0] == 'b' && release <= 1 && !(eq && release == 1)) ||
                        (cond->version->release[0] == 'r' && release <= 2 && !(eq && release == 2)) ||
                        release == 3 && !eq)
                        result = 0;
                    else if (cond->version->release[0] != pyver->release[0] && pyver->serial < cond->version->serial ||
                             !eq && pyver->serial == cond->version->serial)
                        result = 0;
                }
            }
        }
        if (result && cond->mode == PY_VER_COMPATIBLE &&
            (cond->version->significantDigits < 2 || pyver->major != cond->version->major ||
             cond->version->significantDigits == 3 && pyver->minor != cond->version->minor))
            result = 0;
    }
    else if (cond->mode == PY_VER_SMALLER || cond->mode == PY_VER_SMALLER_EQ)
    {
        if (pyver->major > cond->version->major)
            result = 0;
        else if (pyver->major == cond->version->major)
        {
            if (cond->version->significantDigits == 1 && !eq)
                result = 0;
            else if (cond->version->significantDigits > 1 && pyver->minor > cond->version->minor)
                result = 0;
            else if (pyver->minor == cond->version->minor)
            {
                if (cond->version->significantDigits == 2 && !eq)
                    result = 0;
                else if (cond->version->significantDigits > 2 && pyver->micro > cond->version->micro)
                    result = 0;
                else if (cond->version->significantDigits >= 3 && pyver->micro == cond->version->micro)
                {
                    int release;
                    if (pyver->release[0] == 'a')
                        release = 0;
                    else if (pyver->release[0] == 'b')
                        release = 1;
                    else if (pyver->release[0] == 'r')
                        release = 2;
                    else
                        release = 3;

                    if ((cond->version->release[0] == 'a' && release >= 0 && !(eq && release == 0)) ||
                        (cond->version->release[0] == 'b' && release >= 1 && !(eq && release == 1)) ||
                        (cond->version->release[0] == 'r' && release >= 2 && !(eq && release == 2)) ||
                        release == 3 && !eq)
                        result = 0;
                    else if (cond->version->release[0] != pyver->release[0] && pyver->serial > cond->version->serial ||
                             !eq && pyver->serial == cond->version->serial)
                        result = 0;
                }
            }
        }
    }
    else if (cond->mode == PY_VER_ARBITRARY)
    {
        if (cond->version->significantDigits != pyver->significantDigits)
            result = 0;
        else if (pyver->major != cond->version->major)
            result = 0;
        else if (cond->version->significantDigits > 1 && pyver->minor != cond->version->minor)
            result = 0;
        else if (cond->version->significantDigits > 2 &&
                 (pyver->micro != cond->version->micro || strcmp(pyver->release, cond->version->release) != 0 ||
                  pyver->release[0] != '\0' && pyver->serial != cond->version->serial))
            result = 0;
    }
    else
    {
        result = 0;
    }
    return result;
}

int checkPythonPath(PyAppData *config)
{
    HANDLE handle;

    if (config->pythonPath[0] != L'\0')
    {
        handle = CreateFile(config->pythonPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return 0;
        }
        CloseHandle(handle);
        return 1;
    }
    else
    {
        int i;
        int found = 0;
        wchar_t path[MAX_PATH + 1];
        wchar_t *path2;
        PythonVersion pyver;
        PythonVersion pyver2;
        char *verstr;
        PythonVersionCondition *cond;
        HANDLE handle2;

        if (!GetPyVersion("0.0.0", &pyver))
        {
            OutputDebugStringW(L"0.0.0 failed.");
            return 0;
        }

        for (i = 0; searchPathes[i] != NULL; i++)
        {
            wcscpy(path, searchPathes[i]);
            if (!wcscmp(path, L"."))
            {
                wcscpy(path, config->curPath);
            }

            wcscat(path, L"\\python*");
            OutputDebugStringW(path);

            WIN32_FIND_DATA ffd;
            WIN32_FIND_DATA ffd2;

            handle = FindFirstFile(path, &ffd);
            int verlen;

            if (handle != INVALID_HANDLE_VALUE)
            {
                while (1)
                {
                    swprintf(path, L"%s\\%s\\python*.exe", searchPathes[i], ffd.cFileName);
                    OutputDebugStringW(path);
                    handle2 = FindFirstFile(path, &ffd2);
                    if (handle2 != INVALID_HANDLE_VALUE)
                    {
                        while (1)
                        {
                            path2 = ffd2.cFileName;
                            OutputDebugStringW(path2);
                            path2 += 6;
                            verlen = wcslen(path2) - 4;
                            if (verlen > 0)
                            {
                                verstr = (char *)calloc(verlen + 1, sizeof(char));
                                if (verstr == NULL)
                                {
                                    FindClose(handle);
                                    return 0;
                                }
                                WideCharToMultiByte(CP_UTF8, 0, path2, verlen, verstr, verlen, NULL, NULL);
                                if (!GetPyVersion(verstr, &pyver))
                                {
                                    free(verstr);
                                }
                                else
                                {
                                    free(verstr);
                                    int k;
                                    int result = found == 0 || pyver.release[0] == '\0';
                                    for (k = 0; k < config->pyVersionCount && result; k++)
                                    {
                                        OutputDebugStringW(L"version check...");
                                        cond = config->pyVersions[k];
                                        result = checkPythonVersion(&pyver, cond);
                                    }
                                    if (result)
                                    {
                                        if (wcslen(ffd.cFileName) == 6 ||
                                            (_wcsnicmp(ffd.cFileName, ffd2.cFileName, verlen + 6) == 0 &&
                                             wcslen(ffd.cFileName) == 6 + verlen))
                                        {
                                            if (!found)
                                            {
                                                memcpy(&pyver2, &pyver, sizeof(PythonVersion));
                                                swprintf(config->pythonPath, L"%s\\%s\\%s", searchPathes[i],
                                                         ffd.cFileName, ffd2.cFileName);
                                                found = 1;
                                            }
                                            else
                                            {
                                                cond =
                                                    (PythonVersionCondition *)calloc(1, sizeof(PythonVersionCondition));
                                                if (cond == NULL)
                                                    return 0;
                                                cond->version = &pyver2;
                                                cond->mode = PY_VER_BIGGER;
                                                if (checkPythonVersion(&pyver, cond))
                                                {
                                                    memcpy(&pyver2, &pyver, sizeof(PythonVersion));
                                                    swprintf(config->pythonPath, L"%s\\%s\\%s", searchPathes[i],
                                                             ffd.cFileName, ffd2.cFileName);
                                                }
                                                free(cond);
                                            }
                                        }
                                    }
                                }
                            }
                            if (FindNextFile(handle2, &ffd2) == 0)
                                break;
                        }
                    }
                    if (FindNextFile(handle, &ffd) == 0)
                        break;
                }
                FindClose(handle);
            }
        }
        return found;
    }
}

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPTSTR lpCmd, int nShow)
{
    wchar_t LauncherPath[MAX_PATH + 1];
    wchar_t cmdline[32767];
    wchar_t tmpPath[MAX_PATH + 1];
    PROCESS_INFORMATION procInfo = {0};
    int k; // for error finish
    int exitcode = 0;

    config.pythonPath[0] = L'\0';

    // Generate current directory path.

    if (!GetModuleFileName(NULL, LauncherPath, MAX_PATH + 1))
    {
        OutputDebugStringW(L"Could not get the path.");
        return 1;
    }

    wcscpy(config.curPath, LauncherPath);
    wchar_t *ch = wcsrchr(config.curPath, L'\\');
    if (ch == NULL)
    {
        wchar_t *ch = wcsrchr(config.curPath, L'/');
    }
    if (ch == NULL)
    {
        ch = config.curPath;
    }
    *ch = L'\0';

    if (LoadConfig(&config) < 0)
    {
        OutputDebugStringW(L"LoadConfig failed.");
        goto error;
    }

    if (config.pythonPath[0] != L'\0')
    {
        if (config.pythonPath[0] != L'\\' && config.pythonPath[0] != L'/')
        {
            // relative path
            if (wcslen(config.curPath) + wcslen(config.pythonPath) + 1 > MAX_PATH)
                goto error;
            swprintf(tmpPath, L"%s\\%s", config.curPath, config.pythonPath);
            if (PathCchCanonicalizeEx(config.pythonPath, MAX_PATH + 1, tmpPath, 0) != S_OK)
                goto error;
        }
    }

    if (!checkPythonPath(&config))
    {
        OutputDebugStringW(L"checkPythonPath failed.");
        OutputDebugStringW(config.pythonPath);
        goto error;
    }
    else
    {
        OutputDebugStringW(L"Python executable was found:");
        OutputDebugStringW(config.pythonPath);
    }

    swprintf(cmdline, L"--env-set \"PWD=%s\" ", config.curPath);

    if (config.environCount < 0)
    {
        wcscat(cmdline, L"--env-path \"");
        if (config.environs[0][0] != L'\\' && config.environs[0][0] != L'/')
        {
            // relative path
            if (wcslen(config.curPath) + wcslen(config.environs[0]) + 1 > MAX_PATH)
                goto error;
            swprintf(tmpPath, L"%s\\%s", config.curPath, config.environs[0]);
            if (PathCchCanonicalizeEx(tmpPath, MAX_PATH + 1, tmpPath, 0) != S_OK)
                goto error;
        }
        else
        {
            // absolutive path
            if (PathCchCanonicalizeEx(tmpPath, MAX_PATH + 1, config.environs[0], 0) != S_OK)
                goto error;
        }
        wcscat(cmdline, tmpPath);
        free(config.environs[0]);
        wcscat(cmdline, L"\" ");
    }
    else if (config.environCount > 0)
    {
        int i;
        for (i = 0; i < config.environCount; i++)
        {
            wcscat(cmdline, L"--env-path \"");
            if (config.environs[i][0] != L'\\' && config.environs[i][0] != L'/')
            {
                // relative path
                if (wcslen(tmpPath) + wcslen(config.environs[i]) + 1 > MAX_PATH)
                    goto error;
                swprintf(tmpPath, L"%s\\%s", config.curPath, config.environs[i]);
                if (PathCchCanonicalizeEx(tmpPath, MAX_PATH + 1, tmpPath, 0) != S_OK)
                    goto error;
            }
            else
            {
                // absolutive path
                if (PathCchCanonicalizeEx(tmpPath, MAX_PATH + 1, config.environs[i], 0) != S_OK)
                    goto error;
            }
            wcscat(cmdline, tmpPath);
            free(config.environs[i]);
            wcscat(cmdline, L"\" ");
        }
    }

    wchar_t *wargs;
    int length;
    length = MultiByteToWideChar(CP_UTF8, 0, config.args, -1, NULL, 0);
    wargs = (wchar_t *)calloc(length, sizeof(wchar_t));
    if (wargs == NULL)
        goto error;

    MultiByteToWideChar(CP_UTF8, 0, config.args, -1, wargs, length);
    wcscat(cmdline, wargs);
    free(wargs);

    int i;
    for (i = wcslen(cmdline) - 1; i >= 0; i--)
    {
        if (cmdline[i] == L' ')
            cmdline[i] = L'\0';
        else
            break;
    }

    OutputDebugStringW(cmdline);

    CreateProcess(config.pythonPath, cmdline, NULL, NULL, NULL, 0, NULL, NULL, NULL, &procInfo);
#ifdef DEBUG
    WaitForSingleObject(procInfo.hProcess, INFINITE);
#endif
error:
    exitcode = 1;
    for (k = 0; k < config.environCount || k == 0 && config.environCount < 0; k++)
    {
        free(config.environs[k]);
    }
done:
    for (k = 0; k < config.pyVersionCount; k++)
    {
        free(config.pyVersions[k]->version);
        free(config.pyVersions[k]);
    }
    return exitcode;
}
