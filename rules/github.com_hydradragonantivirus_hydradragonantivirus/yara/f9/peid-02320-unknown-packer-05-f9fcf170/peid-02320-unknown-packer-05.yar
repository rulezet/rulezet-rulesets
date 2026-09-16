rule PEiD_02320_Unknown_packer__05__ {
  meta:
    description = "[Unknown packer (05)]"
    ep_only     = "true"

  strings:
    $a = { FA BB ?? ?? B9 ?? ?? 87 E5 87 27 03 E3 91 8A CB 80 E1 ?? D3 C4 91 33 E3 87 27 }

  condition:
    $a
}