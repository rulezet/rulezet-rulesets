rule PEiD_00373_CGM_Graphics_format_ {
  meta:
    description = "[CGM Graphics format]"
    ep_only     = "false"

  strings:
    $a = { 00 2A 08 48 69 4A 61 61 6B 20 32 }

  condition:
    $a
}