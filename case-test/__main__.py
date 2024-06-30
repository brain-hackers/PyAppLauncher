import datetime, subprocess, time
import json
import os
import tkinter

def test_case_check():
    # [
    #     {
    #         "config":"version=3.10\nenviron_file=environ.ini",
    #         "success":true
    #     },
    #     ...
    # ]

    output = "Test start\n\nDate: {}\n\n".format(str(datetime.datetime.now()))

    result = [0, 0]

    with open(__file__+"\\..\\check_list.json", mode="rb") as f:
        cases = json.load(f)

    for case in cases:
        success = False
        with open(__file__+"\\..\\test-app\\config.ini", mode="w+") as f:
            f.write(case["config"])
        if os.path.exists('\\Temp\\result.txt'):
            try:
                os.remove('\\Temp\\result.txt')
            except:
                pass

        want_success = bool(case["success"])

        try:
            subprocess.run([__file__+"\\..\\test-app\\PyAppLauncher.exe"])
        except:
            pass

        success = want_success == os.path.exists('\\Temp\\result.txt')

        if success:
            result[0] += 1
        else:
            result[1] += 1
            output += "Case Failed:\n{}\n\n".format(str(case))
        time.sleep(5)

    output += "Done.\ntotal : {}\nsuccess: {}\nfailed: {}\n".format(result[0]+result[1], result[0], result[1])
    with open(__file__+"\\..\\..\\check_result.log", mode="w+") as f:
        f.write(output)
    exit()

if __name__ == "__main__":
    test_case_check()