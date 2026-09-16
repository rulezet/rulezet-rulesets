rule PEiD_02287_TrueType_Font_file_ {
  meta:
    description = "[TrueType Font file]"
    ep_only     = "false"

  strings:
    $a = { 00 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 4C 54 53 48 }

  condition:
    $a
}