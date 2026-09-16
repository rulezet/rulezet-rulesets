rule PEiD_00277_AVP_Antiviral_Database_ {
  meta:
    description = "[AVP Antiviral Database]"
    ep_only     = "false"

  strings:
    $a = "AVP Antiviral Database"

  condition:
    $a
}