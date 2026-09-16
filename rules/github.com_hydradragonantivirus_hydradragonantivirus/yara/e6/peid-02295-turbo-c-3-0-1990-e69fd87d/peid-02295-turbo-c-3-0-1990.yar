rule PEiD_02295_Turbo_C___3_0_1990_ {
  meta:
    description = "[Turbo C++ 3.0 1990]"
    ep_only     = "true"

  strings:
    $a = { 8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B ?? ?? ?? 8E DA A3 ?? ?? 8C 06 }

  condition:
    $a
}