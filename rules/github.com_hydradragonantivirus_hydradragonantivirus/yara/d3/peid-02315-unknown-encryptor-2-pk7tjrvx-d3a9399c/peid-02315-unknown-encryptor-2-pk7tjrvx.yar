rule PEiD_02315_Unknown_encryptor__2_____PK7Tjrvx__ {
  meta:
    description = "[Unknown encryptor (2) - \"PK7Tjrvx\"]"
    ep_only     = "true"

  strings:
    $a = { 06 B4 52 CD 21 07 E8 ?? ?? B4 62 CD 21 E8 }

  condition:
    $a
}