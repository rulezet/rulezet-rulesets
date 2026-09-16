import "pe"
rule ms_vc_dll2 {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ DLL Method 2"
    group       = "15"
    function    = "0"

  strings:
    $a0 = { 53 56 57 BB 01 ?? ?? ?? 8B ?? 24 14 }

  condition:
    $a0 at pe.entry_point
}