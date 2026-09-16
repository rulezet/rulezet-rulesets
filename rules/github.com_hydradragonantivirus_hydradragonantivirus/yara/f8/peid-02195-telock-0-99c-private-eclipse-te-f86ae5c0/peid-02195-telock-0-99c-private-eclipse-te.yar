rule PEiD_02195_tElock_0_99c__Private_ECLIPSE_____tE__ {
  meta:
    description = "[tElock 0.99c (Private ECLIPSE) -> tE!]"
    ep_only     = "true"

  strings:
    $a = { E9 3F DF FF FF 00 00 00 ?? ?? ?? ?? 04 ?? ?? 00 00 00 00 00 00 00 00 00 24 ?? ?? 00 14 ?? ?? 00 0C ?? ?? 00 00 00 00 00 00 00 00 00 31 ?? ?? 00 1C ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }

  condition:
    $a
}