rule PEiD_02304_TurboBAT_v3_10____5_0__Patched__ {
  meta:
    description = "[TurboBAT v3.10 .. 5.0 (Patched)]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 90 90 90 06 B8 ?? ?? 8E C0 B9 ?? ?? 26 ?? ?? ?? ?? 80 ?? ?? 26 ?? ?? ?? 24 ?? 3A C4 90 90 }

  condition:
    $a
}