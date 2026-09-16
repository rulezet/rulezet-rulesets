rule PEiD_00011__BJFnt_v1_3_ {
  meta:
    description = "[.BJFnt v1.3]"
    ep_only     = "true"

  strings:
    $a = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 }

  condition:
    $a
}