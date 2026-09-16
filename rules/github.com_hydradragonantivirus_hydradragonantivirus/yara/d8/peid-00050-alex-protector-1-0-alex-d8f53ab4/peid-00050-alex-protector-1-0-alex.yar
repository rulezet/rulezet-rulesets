rule PEiD_00050_Alex_Protector_1_0____Alex_ {
  meta:
    description = "[Alex Protector 1.0 -> Alex]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 }

  condition:
    $a
}