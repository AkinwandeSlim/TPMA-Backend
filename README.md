
---

# 🏫 TP Assignment System

Welcome to the **Teaching Practice (TP) Assignment System**, a robust and scalable web application developed for **Sule Lamido University, Kafin Hausa, Jigawa State, Nigeria**, in collaboration with **NITDA**. This project is designed to streamline the coordination of teaching practice programs — automating the management of **trainees**, **supervisors**, and **schools** with intuitive workflows and modern web technologies.

🔗 **Live Demo**: [https://tpma-frontend.vercel.app/](https://tpma-frontend.vercel.app/)

---

## 🎯 Project Overview

The TP Assignment System tackles key educational administrative challenges by offering:

- Centralized management of users (admins, supervisors, trainees)
- School creation and listing by type (Primary, Secondary, Tertiary)
- Foundation for teaching practice assignment and evaluation
- A focus on scalability, maintainability, and user experience

This project showcases my full-stack expertise, combining backend logic, frontend design, and practical UI/UX strategies.

---

## 💡 Why This Project?

As a passionate software engineer, I developed this system to deliver a real-world solution for Nigerian institutions using:

- **Next.js**, **Flask**, and **Tailwind CSS**
- Role-based authentication
- Responsive UI/UX and reusable components
- Scalable architecture for future features

---

## 🚀 Features

### ✅ Current Features (as of April 12, 2025)

- **User Authentication**  
  Secure JWT-based login with role-based access control for Admin, Supervisor, and Trainee.

- **User Management**  
  - Full CRUD for trainees and supervisors  
  - Bulk CSV upload for rapid onboarding

- **School Management**  
  - Add, update, and remove schools  
  - Filter schools by type (Primary, Secondary, Tertiary)

- **Enhanced User Experience**
  - Pagination and debounced search (500ms delay)
  - Persistent queries in URLs (e.g., `/list/schools?search=Green`)
  - Form validation with Zod

- **Frontend Design**
  - Built with **Next.js 14**, **Tailwind CSS**
  - Reusable components like `FormModal`, `Table`, `Pagination`

- **Mock Database**
  - Uses `users.json` for prototyping with a structure ready for PostgreSQL migration

### 🔜 Upcoming Features

- **TP Assignments**: Assign trainees to supervisors and schools with start/end dates  
- **Evaluations**: Supervisor-led assessments of trainee performance  
- **Reporting**: Admin dashboards and insights on program effectiveness  

---

## 🛠️ Tech Stack

### Frontend

- **Next.js 14 (App Router)**
- **Tailwind CSS**
- **React Hook Form + Zod**
- **Axios, React-Toastify**
- **Next-Cloudinary** (for school logos)
- **Custom Hooks** (`useTableSearch`)

### Backend

- **Flask (Python)**
- **JWT + bcrypt** for authentication
- **users.json** as mock DB (migratable to PostgreSQL)
- **Flask-CORS**

---

## 📂 Project Structure

````

tp-assignment-system/
├── src/                    # Frontend (Next.js)
│   ├── app/                # Routes
│   │   ├── (dashboard)/list/
│   │   │   ├── trainees/page.tsx
│   │   │   ├── supervisors/page.tsx
│   │   │   ├── schools/page.tsx
│   ├── components/         # Reusable components
│   ├── forms/              # TraineeForm, SupervisorForm, SchoolForm
│   ├── hooks/              # useTableSearch.ts
│   ├── lib/                # api.ts, validation schemas
├── app.py                  # Flask backend
├── users.json              # Mock data
├── requirements.txt        # Python deps
├── package.json            # Node deps

````

---

## 🏁 Getting Started

### 🔧 Prerequisites

- Node.js v18+
- Python 3.9+
- Git

### 📦 Installation

**Clone the repository:**

```bash
git clone https://github.com/AkinwandeSlim/tp-assignment-system.git
cd tp-assignment-system
````

**Frontend Setup:**

```bash
cd src
npm install
npm run dev
# Runs on http://localhost:3000
```

**Backend Setup:**

```bash
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5000
```

> 🗂️ Ensure `users.json` contains mock data for all roles.

---

## 🧑‍💼 Usage

* **Admin Dashboard**: `/list/trainees`, `/list/supervisors`, `/list/schools`
* **Search & Filter**: Refine records instantly
* **Bulk Upload**: Upload trainees/supervisors via CSV

---

## 🌟 Why Work With Me?

This project reflects my ability to:

* 🧠 Solve real-world education management problems
* 💻 Build scalable and secure full-stack systems
* 💡 Prioritize user experience with intuitive workflows
* 🧱 Lay strong foundations for future enhancements

I combine **technical expertise** with a **user-focused mindset** to deliver impactful systems tailored to local contexts like **Nigerian universities**.

---

## 🤝 Contributing

Want to help improve the system?

1. Fork the repo
2. Create a branch: `git checkout -b feature/YourFeature`
3. Commit: `git commit -m "Add YourFeature"`
4. Push: `git push origin feature/YourFeature`
5. Open a Pull Request

> Ensure changes are clearly described and tested!

---

## 🔮 Future Enhancements

* 🏫 TP Assignments with dedicated dashboard
* ✅ Supervisor Evaluations
* 🧩 Migration to PostgreSQL
* 🧪 Tests: Jest (frontend), pytest (backend)
* 🚀 Performance optimizations for large data loads

---

## 👤 Author

**Akinwande Alex (AkinwandeSlim)**
📧 Email: [`alexdata2022@gmail.com`](mailto:alexdata2022@gmail.com)
🔗 GitHub: [@AkinwandeSlim](https://github.com/AkinwandeSlim)

---

> Built with 💻 and ☕ by **AkinwandeSlim** for Sule Lamido University, in partnership with **NITDA**. Let’s transform education management in Nigeria — one system at a time!

```


