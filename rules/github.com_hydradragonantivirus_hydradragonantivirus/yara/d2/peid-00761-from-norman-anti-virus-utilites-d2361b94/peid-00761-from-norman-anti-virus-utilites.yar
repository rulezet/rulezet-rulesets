rule PEiD_00761_from_NORMAN_Anti_Virus_Utilites_ {
  meta:
    description = "[from NORMAN Anti-Virus Utilites]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 5B 52 45 2F 4E 44 44 53 5D 0D 0A }

  condition:
    $a
}