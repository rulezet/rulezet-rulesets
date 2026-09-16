import "pe"
rule ms_vc_dll1 {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ DLL Method 1"
    group       = "15"
    function    = "0"

  strings:
    $a0 = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 }

  condition:
    $a0 at pe.entry_point
}