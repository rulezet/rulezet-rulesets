rule PEiD_00102_APEX_C__BLT_Apex_4_0_____500mhz_ {
  meta:
    description = "[APEX_C (BLT Apex 4.0) -> 500mhz]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 }

  condition:
    $a
}