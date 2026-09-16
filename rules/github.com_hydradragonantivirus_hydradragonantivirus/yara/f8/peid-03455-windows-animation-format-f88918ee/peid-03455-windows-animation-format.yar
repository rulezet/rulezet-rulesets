rule PEiD_03455_Windows_Animation_format_ {
  meta:
    description = "[Windows Animation format]"
    ep_only     = "false"

  strings:
    $a = { 52 49 46 46 ?? ?? ?? ?? 41 43 4F 4E 4C 49 53 54 }

  condition:
    $a
}