rule TTP_XOR_WriteProcessMemory_a91a {
  strings:
    $key_a91a = { fe 68 [2] cc 4a [2] ca 7f [2] e4 7f [2] db 63 }

  condition:
    any of them
}