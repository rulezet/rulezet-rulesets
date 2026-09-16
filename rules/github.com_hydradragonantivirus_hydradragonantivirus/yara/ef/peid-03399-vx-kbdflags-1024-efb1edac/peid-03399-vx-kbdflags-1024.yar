rule PEiD_03399_Vx__KBDflags_1024_ {
  meta:
    description = "[Vx: KBDflags.1024]"
    ep_only     = "true"

  strings:
    $a = { 8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22 }

  condition:
    $a
}