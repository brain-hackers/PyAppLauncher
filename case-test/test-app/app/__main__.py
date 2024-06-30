import os
import sys
import tkinter as tk

if __name__ == "__main__" and ("--show" in sys.argv or (len(sys.argv) > 0 and not sys.executable.endswith("python{}.exe".format(sys.argv[0])))):
    with open("\\Temp\\result.txt", mode='w+') as f:
        f.write('')
    root = tk.Tk()
    label = tk.Label(root, text=f'Hello World\n\nargs: {sys.argv}\n\nenvirons:\n{os.environ}')
    label.pack()

    root.mainloop()
else:
    try:
        os.remove('\\Temp\\result.txt')
    except:
        pass