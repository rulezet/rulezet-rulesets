rule PEiD_01262_Nakedbind_1_0____nakedcrew_ {
  meta:
    description = "[Nakedbind 1.0 -> nakedcrew]"
    ep_only     = "true"

  strings:
    $a = { 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00 }

  condition:
    $a
}