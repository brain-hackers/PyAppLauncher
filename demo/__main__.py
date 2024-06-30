import tkinter as tk

description = '''About PyAppLauncher
PyAppLauncherは、WindowsCE向けのPython製アプリのパッケージングを容易にするために開発されました。
詳しくは下記リポジトリを参照してください。
https://github.com/brain-hackers/PyAppLauncher'''

def main():
    root = tk.Tk()
    root.title("PyAppLauncher")

    descriptionBox = tk.Label(root, text=description)
    descriptionBox.pack()

    root.mainloop()

if __name__ == "__main__":
    main()