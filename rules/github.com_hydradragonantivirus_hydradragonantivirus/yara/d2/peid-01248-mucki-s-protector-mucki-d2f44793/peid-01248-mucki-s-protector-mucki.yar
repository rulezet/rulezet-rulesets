rule PEiD_01248_mucki_s_protector____mucki_ {
  meta:
    description = "[mucki's protector -> mucki]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 E9 }

  condition:
    $a
}