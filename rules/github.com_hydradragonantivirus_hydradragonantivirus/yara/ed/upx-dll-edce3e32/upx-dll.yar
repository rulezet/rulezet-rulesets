import "pe"
rule upx_dll {
  meta:
    author      = "PEiD"
    description = "UPX 0.80 - 1.24 DLL -> Markus & Laszlo"
    group       = "183"
    function    = "0"

  strings:
    $a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

  condition:
    $a0 at pe.entry_point
}