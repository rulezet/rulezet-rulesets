rule macos_toydrop_pkg_null_padded_trailer: dropper {
  meta:
    description = "MACOS.ADLOAD"

  condition:
    100KB < filesize and filesize < 3MB
    and uint32be(0) == 0x78617221
    and uint32be(filesize - 4) < filesize - 32 - 16 - 50
    and uint32be(filesize - 4) > 0x30000
    and for all i in (1..32): (uint8(uint32be(filesize - 4) - i) == 0x00)
    and for all i in (0..5): (uint16(uint32be(filesize - 4) + 32 + 16 + i * 2) != 0x0000)
}