rule PEiD_00508_E2C_by_DoP_ {
  meta:
    description = "[E2C by DoP]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? BF ?? ?? B9 ?? ?? FC 57 F3 A5 C3 }

  condition:
    $a
}