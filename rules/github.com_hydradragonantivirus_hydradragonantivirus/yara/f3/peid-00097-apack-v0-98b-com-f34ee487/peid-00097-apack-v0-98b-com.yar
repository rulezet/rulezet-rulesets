rule PEiD_00097_aPack_v0_98b__com__ {
  meta:
    description = "[aPack v0.98b (com)]"
    ep_only     = "false"

  strings:
    $a = { BE ?? ?? BF ?? ?? 8B CF FC 57 F3 A4 C3 BF ?? ?? 57 57 BE ?? ?? B2 ?? BD ?? ?? 50 A4 }

  condition:
    $a
}