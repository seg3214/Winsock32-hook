# Winsock32-hook


A high-performance **C-based DLL** designed to intercept and manipulate network traffic in real-time. By injecting into a target process, it hooks Windows Socket 32 (`ws2_32.dll`) `send` and `recv` functions, allowing users to modify packet payload before it exits the user mode or reaches the application logic.

## 🚀 Key Features
* **Dual-Stage Hooking**: Intercepts functions at both the prologue (pre-execution) and epilogue (post-execution), providing full access to function arguments and return values.
* **Low-Overhead Telemetry**: Utilizes a pagefile-backed mapped ring buffer to store user-defined structs. This ensures high-speed data IPC and persistence without heavy disk I/O.
* **Dynamic Console Management**: Automatically detects or allocates a console for the target process to provide real-time logging.
* **Clean Detachment**: A dedicated listener thread that restores memory protections, uninstalls hooks, terminates the ring buffer, and reverts the console state to ensure the target process remains stable after unloading.

## ⚙️ How It Works
* **Manual Hooking**: Avoids third-party libraries. Hooks are installed manually via Inline Assembler and Windows API to redirect execution flow.
* **C-Style Callbacks**: Low-level ASM hooks are redirected to standard C functions for easier packet logic manipulation.
* **Naked Controller Functions**: Uses `__declspec(naked)` functions to manage the stack, registers, and execution at the ASM level.				
* **Trampoline Execution**: Employs a trampoline system to execute "stolen bytes" from the original function prologue before jumping back to the target's original code path.

> ## ⚠️ Legal Disclaimer
> 
> **This tool is for educational and research purposes only.** 
>
>### Research Methodology
> Visual demonstrations were captured in a controlled environment for the purpose of validating system stability and latency under real-world conditions. 
> ### Use at Your Own Risk
> The author (and any contributors) are NOT responsible for:
> *   **Account Actions:** Any bans, suspensions, or penalties applied to your accounts by game developers or anti-cheat systems (e.g., VAC, BattlEye, Easy Anti-Cheat).
> *   **System Damage:** Any data loss, hardware failure, or system instability caused by the use of this software.
> *   **Legal Consequences:** Any misuse of this tool that violates local laws or third-party Terms of Service.
> 
> ### License
> This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. 
>
> ### Third-Party Notices
> This project incorporates bundled code from third parties. For details and full license texts, please see the [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES) file.


