# React + Vite

## Run the Project

### 1. Install frontend dependencies

Open PowerShell in the project folder and run:

```powershell
cd "D:\COLLEGE 25-26\CN PROJECT"
npm install
```

### 2. Set up the Python backend

Open a second PowerShell terminal:

```powershell
cd "D:\COLLEGE 25-26\CN PROJECT"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### 3. Start the backend

In the second terminal, run:

```powershell
uvicorn backend:app --reload --host 0.0.0.0 --port 8002
```

The backend API will be available at `http://localhost:8002`.

### 4. Start the frontend

In the first terminal, run:

```powershell
npm run dev
```

Open the Vite URL shown in the terminal, usually `http://localhost:5173`.

### Windows packet capture requirement

The backend uses Scapy to capture network packets. On Windows, install [Npcap](https://npcap.com/) and run the backend terminal as Administrator if packet capture does not start. The Live Packets view shows up to the latest 100 captured packets; use the **ICMP** filter to isolate `ping` request/reply packets. A successful `ping` alone does not mean the dashboard has displayed it yet if the network is busy.

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.
