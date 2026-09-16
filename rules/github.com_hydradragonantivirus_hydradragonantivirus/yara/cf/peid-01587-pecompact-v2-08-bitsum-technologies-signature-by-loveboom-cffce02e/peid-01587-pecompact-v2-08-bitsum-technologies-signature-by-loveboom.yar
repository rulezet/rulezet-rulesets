rule PEiD_01587_PeCompact_v2_08____Bitsum_Technologies_signature_by_loveboom__ {
  meta:
    description = "[PeCompact v2.08 -> Bitsum Technologies(signature by loveboom)]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D }

  condition:
    $a
}