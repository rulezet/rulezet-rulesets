rule PEiD_01493_PE_Diminisher_v0_1_ {
  meta:
    description = "[PE Diminisher v0.1]"
    ep_only     = "true"

  strings:
    $a = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 }

  condition:
    $a
}