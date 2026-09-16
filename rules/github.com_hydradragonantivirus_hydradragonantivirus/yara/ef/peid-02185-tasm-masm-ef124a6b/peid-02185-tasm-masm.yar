rule PEiD_02185_TASM___MASM_ {
  meta:
    description = "[TASM / MASM]"
    ep_only     = "true"

  strings:
    $a = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 }

  condition:
    $a
}