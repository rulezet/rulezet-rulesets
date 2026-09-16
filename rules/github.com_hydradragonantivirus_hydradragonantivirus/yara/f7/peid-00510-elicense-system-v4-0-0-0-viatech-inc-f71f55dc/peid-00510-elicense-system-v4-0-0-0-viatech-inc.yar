rule PEiD_00510_Elicense_System_V4_0_0_0____ViaTech_Inc_ {
  meta:
    description = "[Elicense System V4.0.0.0 -> ViaTech Inc]"
    ep_only     = "false"

  strings:
    $a = { 00 00 00 00 63 79 62 00 65 6C 69 63 65 6E 34 30 2E 64 6C 6C 00 00 00 00 }

  condition:
    $a
}