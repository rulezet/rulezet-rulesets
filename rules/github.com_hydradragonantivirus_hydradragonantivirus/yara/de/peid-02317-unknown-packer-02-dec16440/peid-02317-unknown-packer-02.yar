rule PEiD_02317_Unknown_packer__02__ {
  meta:
    description = "[Unknown packer (02)]"
    ep_only     = "true"

  strings:
    $a = { FA 8C DE 8C CF 8E DF 8E C7 83 C7 ?? BB }

  condition:
    $a
}