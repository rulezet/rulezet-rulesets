rule PEiD_03497_X_Pack_v1_4_2_ {
  meta:
    description = "[X-Pack v1.4.2]"
    ep_only     = "false"

  strings:
    $a = { 72 ?? C3 8B DE 83 ?? ?? C1 ?? ?? 8C D8 03 C3 8E D8 8B DF 83 ?? ?? C1 ?? ?? 8C C0 03 C3 8E C0 C3 }

  condition:
    $a
}