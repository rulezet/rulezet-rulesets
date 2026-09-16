rule PEiD_00061_Amiga_IFF_ILBM_Graphics_format_ {
  meta:
    description = "[Amiga IFF/ILBM Graphics format]"
    ep_only     = "false"

  strings:
    $a = { 46 4F 52 4D ?? ?? ?? ?? 49 4C 42 4D 42 4D 48 44 }

  condition:
    $a
}