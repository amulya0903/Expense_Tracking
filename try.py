import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt


class PersonalFinanceApp:
    def __init__(self, root, user_id, admin=False):
        self.root = root
        self.root.title("Personal Finance Dashboard")

        # Database connection
        self.conn = sqlite3.connect('finance.db')
        self.cursor = self.conn.cursor()

        # Variables to store user input
        self.expense_var = tk.DoubleVar()
        self.category_var = tk.StringVar()
        self.user_id = user_id
        self.admin = admin  # Indicates whether the app is in admin mode

        # Data structures to store categorized expenses
        self.expenses = {}
        self.categories = set()

        # Create a unique expenses table for the user
        self.expenses_table = f"expenses_{user_id}"
        self.create_expenses_table()

        # GUI components
        self.create_input_frame()
        self.create_dashboard_frame()

        # If in admin mode, create a user list
        if self.admin:
            self.create_user_list()
        else:
            # Fetch and display the user's expenses
            self.fetch_user_expenses()
            self.update_dashboard()

    def create_expenses_table(self):
        # Create a unique expenses table for the user
        create_table_query = f'''
            CREATE TABLE IF NOT EXISTS {self.expenses_table} (
                expense_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                category TEXT,
                amount REAL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        '''
        self.cursor.execute(create_table_query)
        self.conn.commit()

    def create_input_frame(self):
        input_frame = ttk.Frame(self.root, padding="10")
        input_frame.grid(row=0, column=0, padx=10, pady=10)

        # Expense input
        ttk.Label(input_frame, text="Expense:", font=('Helvetica', 12), foreground='#000000').grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(input_frame, textvariable=self.expense_var, font=('Helvetica', 12)).grid(row=0, column=1, padx=5, pady=5)

        # Category input
        ttk.Label(input_frame, text="Category:", font=('Helvetica', 12), foreground='').grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(input_frame, textvariable=self.category_var, font=('Helvetica', 12)).grid(row=1, column=1, padx=5, pady=5)

        # Add Expense button
        ttk.Button(input_frame, text="Add Expense", command=self.add_expense, style='Accent.TButton').grid(row=2, column=0, columnspan=2, pady=10)
      
        ttk.Button(input_frame, text="Remove Expense", command=self.remove_expense, style='Accent.TButton').grid(row=3, column=0, columnspan=2, pady=5)

    def create_dashboard_frame(self):
        dashboard_frame = ttk.Frame(self.root, padding="10")
        dashboard_frame.grid(row=0, column=1, padx=10, pady=10)

        # Pie chart to display spending patterns
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=dashboard_frame)
        self.canvas.get_tk_widget().pack(side=tk.LEFT)

        # Frame for expenses list
        expenses_frame = ttk.Frame(dashboard_frame, padding="10")
        expenses_frame.pack(side=tk.RIGHT)

        # Listbox to display expenses
        self.expenses_listbox = tk.Listbox(expenses_frame, height=10, width=30)
        self.expenses_listbox.pack()

        # Call update_dashboard to display the pie chart
        self.update_dashboard()

    def add_expense(self):
        expense = self.expense_var.get()
        category = self.category_var.get()

        # Check for empty fields
        if not expense or not category:
            messagebox.showerror("Error", "Expense and category cannot be empty")
            return

        # Update data structures
        if category not in self.expenses:
            self.expenses[category] = 0
        self.expenses[category] += expense
        self.categories.add(category)

        # Update the database
        self.update_database(category, expense)

        # Clear input fields
        self.expense_var.set(0.0)
        self.category_var.set("")

        # Update the dashboard
        self.update_dashboard()

    def remove_expense(self):
        category = self.category_var.get()

        # Check for empty field
        if not category:
            messagebox.showerror("Error", "Category cannot be empty for removing expense")
            return

        # Check if the category exists
        if category not in self.expenses:
            messagebox.showerror("Error", f"No expenses found for category: {category}")
            return

        # Remove the expense for the specified category
        removed_amount = self.expenses.pop(category, 0)

        # Update the database
        self.update_database(category, -removed_amount)

        # Update the dashboard
        self.update_dashboard()

    def update_database(self, category, expense):
        # Update the user's expenses table in the database
        query = f"INSERT INTO {self.expenses_table} (user_id, category, amount) VALUES (?, ?, ?)"
        self.cursor.execute(query, (self.user_id, category, expense))
        self.conn.commit()

    def fetch_user_expenses(self):
        # Fetch user's expenses from the user's expenses table
        query = f"SELECT category, SUM(amount) FROM {self.expenses_table} WHERE user_id = ? GROUP BY category"
        self.cursor.execute(query, (self.user_id,))
        rows = self.cursor.fetchall()

        # Update data structures
        for row in rows:
            category, amount = row
            self.expenses[category] = amount
            self.categories.add(category)

    def update_dashboard(self):
        # Update pie chart
        self.ax.clear()

        if not self.expenses:
            # No expenses to show
            self.fig.canvas.draw()
            return

        labels = []
        amounts = []

        for category, amount in self.expenses.items():
            if amount > 0:
                labels.append(category)
                amounts.append(amount)

        if not labels:
            # No non-zero expenses to show
            self.fig.canvas.draw()
            return

        # Calculate total expense amount
        total_expense = sum(amounts)

        # Format amounts in rupees
        formatted_amounts = [f'₹{amount:.2f}' for amount in amounts]

        # Calculate percentages manually
        percentages = [(amount / total_expense) * 100 for amount in amounts]

        # Create labels with category and percentage
        label_texts = [f'{label}\n({formatted_amounts[i]}, {percentages[i]:.1f}%)' for i, label in enumerate(labels)]

        # Update labels and autopct based on total expense
        self.ax.pie(amounts, labels=label_texts, startangle=90)
        self.ax.axis("equal")  # Equal aspect ratio ensures that the pie is drawn as a circle
        self.fig.canvas.draw()
        self.expenses_listbox.delete(0, tk.END)  # Clear the listbox
        for label, amount in zip(labels, formatted_amounts):
            self.expenses_listbox.insert(tk.END, f"{label}: {amount}")

    def create_user_list(self):
        user_list_frame = ttk.Frame(self.root, padding="10")
        user_list_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

        # Label for user list
        ttk.Label(user_list_frame, text="User List:", font=('Helvetica', 14, 'bold'), foreground='#000000').grid(row=0, column=0, sticky="w")

        # Fetch user data from the database
        query = "SELECT user_id, username FROM users"
        self.cursor.execute(query)
        users = self.cursor.fetchall()

        # Display user list
        for user in users:
            user_id, username = user
            ttk.Label(user_list_frame, text=f"{username} (ID: {user_id})", font=('Helvetica', 12)).grid(row=user_id, column=0, sticky="w", pady=5)
            ttk.Button(user_list_frame, text="View Expenses", command=lambda u=user_id: self.view_user_expenses(u), style='Accent.TButton').grid(row=user_id, column=1, padx=5)

    def view_user_expenses(self, user_id):
        # Open a new window to display expenses for the selected user
        expenses_root = tk.Toplevel(self.root)
        expenses_app = PersonalFinanceApp(expenses_root, user_id)

class LoginRegisterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login/Register")

        # Database connection
        self.conn = sqlite3.connect('finance.db')
        self.cursor = self.conn.cursor()

        # Variables to store user input
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()

        # GUI components
        self.create_styles()
        self.create_login_register_frame()

    def create_styles(self):
        # Create a custom style for buttons
        self.root.style = ttk.Style()
        self.root.style.configure('Accent.TButton', font=('Helvetica', 12), background='#4CAF50')

    def create_login_register_frame(self):
        login_register_frame = ttk.Frame(self.root, padding="10")
        login_register_frame.grid(row=0, column=0, padx=10, pady=10)

        ttk.Label(login_register_frame, text="Username:", font=('Helvetica', 12), foreground='#000000').grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(login_register_frame, textvariable=self.username_var, font=('Helvetica', 12)).grid(row=0, column=1, padx=5, pady=5)

        # Password input
        ttk.Label(login_register_frame, text="Password:", font=('Helvetica', 12), foreground='#000000').grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(login_register_frame, textvariable=self.password_var, show="*", font=('Helvetica', 12)).grid(row=1, column=1, padx=5, pady=5)

        # Login button
        ttk.Button(login_register_frame, text="Login", command=self.login, style='Accent.TButton').grid(row=2, column=0, padx=5, pady=10)

        # Register button
        ttk.Button(login_register_frame, text="Register", command=self.register, style='Accent.TButton').grid(row=2, column=1, padx=5, pady=10)

        # Set the focus on the username entry field
        login_register_frame.focus_set()
        login_register_frame.bind("<Return>", lambda event: self.login())  # Trigger login on Enter key press

        # Center the frame on the screen
        login_register_frame.place(relx=0.5, rely=0.5, anchor="center")

    def clear_input_fields(self):
        # Clear input fields
        self.username_var.set("")
        self.password_var.set("")

    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()

        # Check for empty fields
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return

        # Check credentials in the database
        query = "SELECT user_id, password FROM users WHERE username = ?"
        self.cursor.execute(query, (username,))
        result = self.cursor.fetchone()

        if result and check_password_hash(result[1], password):
            # Open the finance app for the user
            finance_root = tk.Toplevel(self.root)
            finance_app = PersonalFinanceApp(finance_root, user_id=result[0])
            # Clear input fields after login
            self.clear_input_fields()
        else:
            messagebox.showerror("Login Error", "Invalid username or password")

    def register(self):
        username = self.username_var.get()
        password = self.password_var.get()

        # Check for empty fields
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return

        # Hash the password using werkzeug.security
        hashed_password = generate_password_hash(password)

        # Check if the username already exists
        query = "SELECT * FROM users WHERE username = ?"
        self.cursor.execute(query, (username,))
        existing_user = self.cursor.fetchone()

        if not existing_user:
            # Add the new user to the database with the hashed password
            query = "INSERT INTO users (username, password) VALUES (?, ?)"
            self.cursor.execute(query, (username, hashed_password))
            self.conn.commit()
            messagebox.showinfo("Registration Successful", "Account created successfully!")
            # Clear input fields after registration
            self.clear_input_fields()
        else:
            messagebox.showerror("Registration Error", "Username already exists. Please choose a different username.")

if __name__ == "__main__":
    # Create tables if not exists
    conn = sqlite3.connect('finance.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

    root = tk.Tk()
    app = LoginRegisterApp(root)
    root.mainloop()
