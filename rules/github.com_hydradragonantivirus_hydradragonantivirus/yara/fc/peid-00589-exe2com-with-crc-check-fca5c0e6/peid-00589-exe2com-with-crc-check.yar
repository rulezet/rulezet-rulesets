import "pe"
rule PEiD_00589_EXE2COM__With_CRC_check__ {
  meta:
    description = "[EXE2COM (With CRC check)]"
    ep_only     = "true"

  strings:
    $a = { B3 ?? B9 ?? ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 43 49 32 E4 03 D0 E3 }

  condition:
    $a at pe.entry_point
}