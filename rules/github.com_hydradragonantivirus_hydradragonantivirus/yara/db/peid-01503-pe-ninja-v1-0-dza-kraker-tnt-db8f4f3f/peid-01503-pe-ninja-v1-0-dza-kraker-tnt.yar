rule PEiD_01503_PE_Ninja_v1_0_____DzA_kRAker_TNT_ {
  meta:
    description = "[PE Ninja v1.0 -> +DzA kRAker TNT]"
    ep_only     = "true"

  strings:
    $a = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $a
}