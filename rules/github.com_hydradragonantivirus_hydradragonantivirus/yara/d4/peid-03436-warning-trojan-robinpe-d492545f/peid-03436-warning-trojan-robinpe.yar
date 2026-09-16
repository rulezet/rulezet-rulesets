rule PEiD_03436_WARNING____TROJAN____RobinPE_ {
  meta:
    description = "[WARNING -> TROJAN -> RobinPE]"
    ep_only     = "true"

  strings:
    $a = { 60 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 }

  condition:
    $a
}