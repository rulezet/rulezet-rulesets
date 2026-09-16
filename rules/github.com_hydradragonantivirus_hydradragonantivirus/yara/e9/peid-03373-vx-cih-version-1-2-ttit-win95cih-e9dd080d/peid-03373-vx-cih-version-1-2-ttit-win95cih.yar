rule PEiD_03373_Vx__CIH_Version_1_2_TTIT____WIN95CIH____ {
  meta:
    description = "[Vx: CIH Version 1.2 TTIT (! WIN95CIH !)]"
    ep_only     = "true"

  strings:
    $a = { 55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D }

  condition:
    $a
}