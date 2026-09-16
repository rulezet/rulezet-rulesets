rule bcpp_dll2 {
  meta:
    author      = "PEiD"
    description = "Borland C++ DLL Method 2"
    group       = "10"
    function    = "0"

  strings:
    $a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 }

  condition:
    $a0
}