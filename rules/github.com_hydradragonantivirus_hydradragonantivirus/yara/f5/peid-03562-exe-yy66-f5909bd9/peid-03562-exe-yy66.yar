rule PEiD_03562_____EXE__________yy66_ {
  meta:
    description = "[convert base64 to ascii w5DDhMOGw6ZFWEXCusOPwrLCosOGw7cgLT4geXk2Ng==]"
    ep_only     = "true"

  strings:
    $a = { 68 78 18 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 }

  condition:
    $a
}