rule PEiD_00684_eXPressor_v1_3____CGSoftLabs_ {
  meta:
    description = "[eXPressor v1.3 -> CGSoftLabs]"
    ep_only     = "false"

  strings:
    $a = "ExPr-v.1.3."

  condition:
    $a
}