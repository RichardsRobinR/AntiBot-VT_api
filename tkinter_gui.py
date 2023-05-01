import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from tkinter.messagebox import showinfo
from functools import partial
import virus_total_api

virus_total_api_obj = virus_total_api.VirusTotalApi()

result_list = {}
def browse_file():
    file_path = filedialog.askopenfilename()
    print(file_path)
    request_file(file_path)
    

def request_file(file_path):
    result_list = virus_total_api_obj.file_report(file_path=file_path)
    if result_list != " ":
        open_table(result_list)
    else:
        showinfo(title='New File Found!!',message='Queuing....Estimated Time 1 Min')
        

def on_closing_new_win_table(new_win_table):
    # win_button.config(bg="red")
    new_win_table.destroy()


def open_table(result_list):
    new_win_table = tk.Toplevel()
    new_win_table.geometry("700x400")
    tree = ttk.Treeview(new_win_table)
    tree["columns"] = ("one", "two")
    tree.column("#0", width=100,) #stretch=tk.NO
    tree.column("one", width=100,)
    tree.column("two", width=100, )

    tree.heading("#0", text="Serial Number",anchor="center")
    tree.heading("one", text="Anti-Virus Engine",anchor="center")
    tree.heading("two", text="Result",anchor="center")

    i = 0
    for engine, result in result_list:
        i += 1 
        if str(result['result']) == "None":
            tree.insert("", "end", text=i, values=(engine, result['result']))
        else:
            tree.insert("", "end", text=i, values=(engine, result['result']),tags="red_tag")
            tree.tag_configure(tagname="red_tag", background="red")
        # print("{}: {}".format(engine, result['result']))
    tree.pack(fill="both", expand=1)

    scrollbar = ttk.Scrollbar(tree)
    scrollbar.pack(side="right", fill="y")

    tree.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=tree.yview)

    new_win_table.protocol("WM_DELETE_WINDOW", func=partial(on_closing_new_win_table,new_win_table))


root = tk.Tk()
root.geometry("750x450")
root.title("AntiBot-VT")
root.resizable(False, False)

mainframe = tk.Frame(root, width=400, height=500,)
mainframe.place(relx=0.5, rely=0.5, anchor="center")


bold_font = ("Arial", 36, "bold")
label = tk.Label(mainframe, text="AntiBot-VT", font=bold_font)
label.grid(row=0, column=0,padx=60,pady=20)

frame = tk.Frame(mainframe, width=400, height=500,highlightbackground='light blue',highlightthickness=3)
# Position the frame in the center of the window
# frame.place(relx=0.5, rely=0.5, anchor="w")
frame.grid(row=0, column=1,padx=20,pady=20)

image = tk.PhotoImage(file="tst.png")
image_label = tk.Label(frame, image=image,height=160,width=140,background="light blue")
image_label.grid(row=0, column=0,padx=20,pady=20)

button = tk.Button(frame, text="Upload File",command=browse_file, width=20,height=2,font = ("Arial", 8, "bold"))
button.grid(row=1, column=0,padx=20,pady=20)

root.mainloop()
