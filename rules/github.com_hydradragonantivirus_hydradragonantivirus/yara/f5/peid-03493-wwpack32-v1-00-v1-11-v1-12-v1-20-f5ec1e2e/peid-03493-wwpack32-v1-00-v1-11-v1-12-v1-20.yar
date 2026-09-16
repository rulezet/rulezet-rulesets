rule PEiD_03493_WWPack32_v1_00__v1_11__v1_12__v1_20_ {
  meta:
    description = "[WWPack32 v1.00, v1.11, v1.12, v1.20]"
    ep_only     = "true"

  strings:
    $a = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 }

  condition:
    $a
}