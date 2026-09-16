rule PEiD_00272_Audio_CD_file_ {
  meta:
    description = "[Audio-CD file]"
    ep_only     = "false"

  strings:
    $a = { 52 49 46 46 ?? ?? ?? ?? 43 44 44 41 66 6D 74 }

  condition:
    $a
}