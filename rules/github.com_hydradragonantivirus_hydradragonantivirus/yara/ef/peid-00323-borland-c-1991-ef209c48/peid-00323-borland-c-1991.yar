rule PEiD_00323_Borland_C___1991_ {
  meta:
    description = "[Borland C++ 1991]"
    ep_only     = "true"

  strings:
    $a = { 2E 8C 06 ?? ?? 2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F }

  condition:
    $a
}