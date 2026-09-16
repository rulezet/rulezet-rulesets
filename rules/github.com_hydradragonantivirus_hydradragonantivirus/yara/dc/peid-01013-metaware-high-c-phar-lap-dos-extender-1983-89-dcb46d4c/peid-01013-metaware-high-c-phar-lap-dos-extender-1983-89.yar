rule PEiD_01013_MetaWare_High_C___Phar_Lap_DOS_Extender_1983_89_ {
  meta:
    description = "[MetaWare High C + Phar Lap DOS Extender 1983-89]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 8E D8 B8 ?? ?? CD 21 A3 ?? ?? 3C 03 7D ?? B4 09 }

  condition:
    $a
}