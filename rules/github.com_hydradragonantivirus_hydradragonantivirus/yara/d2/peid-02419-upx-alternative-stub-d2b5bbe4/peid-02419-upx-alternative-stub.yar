rule PEiD_02419_UPX_Alternative_stub_ {
  meta:
    description = "[UPX Alternative stub]"
    ep_only     = "true"

  strings:
    $a = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }

  condition:
    $a
}