rule capa_pe_file: CAPA {
  meta:
    description = "match in PE files. used by all further CAPA rules"
    author      = "Arnim Rupp"

  condition:
    uint16be(0) == 0x4d5a
    or uint16be(0) == 0x558b
    or uint16be(0) == 0x5649
}