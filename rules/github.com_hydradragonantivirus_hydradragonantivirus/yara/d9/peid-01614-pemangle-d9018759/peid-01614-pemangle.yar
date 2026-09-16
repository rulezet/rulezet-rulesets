rule PEiD_01614_PEMangle_ {
  meta:
    description = "[PEMangle]"
    ep_only     = "true"

  strings:
    $a = { 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3 }

  condition:
    $a
}