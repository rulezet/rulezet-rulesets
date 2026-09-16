rule PEiD_01010_Matrix_Dongle____TDi_GmbH_ {
  meta:
    description = "[Matrix Dongle -> TDi GmbH]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 E8 00 00 00 00 59 5A 2B CA 2B D1 E8 1A FF FF FF }

  condition:
    $a
}