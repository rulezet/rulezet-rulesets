rule TTP_XOR_WriteProcessMemory_a91f {
  strings:
    $key_a91f = { fe 6d [2] cc 4f [2] ca 7a [2] e4 7a [2] db 66 }

  condition:
    any of them
}