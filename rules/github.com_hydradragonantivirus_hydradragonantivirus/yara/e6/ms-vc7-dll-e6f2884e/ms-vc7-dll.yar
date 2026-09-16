import "pe"
rule ms_vc7_dll {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ 7.0 DLL Method 1"
    group       = "15"
    function    = "0"

  strings:
    $a0 = { 55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84 }

  condition:
    $a0 at pe.entry_point
}