rule PEiD_02064_Sharp_GPB_Graphics_format_ {
  meta:
    description = "[Sharp GPB Graphics format]"
    ep_only     = "false"

  strings:
    $a = { 4D 00 00 00 00 ?? ?? ?? ?? 08 00 00 00 03 00 00 }

  condition:
    $a
}