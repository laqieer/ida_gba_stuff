# ida_gba_stuff
Useful stuff when reversing gba games with [IDA](https://hex-rays.com/)

## Installation
Copy to the installation directory of your IDA.

## Note
- The directory 'fe' is for fire emblem exclusively, others work for all gba games.
- [GBA loader](https://github.com/laqieer/ida_gba_stuff/blob/master/loaders/GBA_Loader.py) is updated for **IDA 9.3** and works in both the GUI and headless [idalib](https://hex-rays.com/blog/ida-pro-9-0-idalib). The `.idc` scripts still run on IDA 7.0–9.x through IDA's `idc.idc` compatibility layer; `fe/scripts/proc.py` is fixed for IDA 9.x / Python 3 (Python-2 `print` statements, integer division, and the removed `MakeFunction`/`find_binary`/`GetString` → `add_func`/`find_bytes`/`get_strlit_contents`).
- The IDA 9.x port replaces the removed Python `idaapi.cvar.inf` writes with the `ida_ida.inf_set_start_ea/ip` setters (the old form is `None` under idalib). An earlier [GBA loader for IDA 9.0](https://github.com/vineberry/ida_gba_stuff-9.0/blob/master/loaders/GBA_Loader.py) by @vineberry exists too.
