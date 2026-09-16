rule TTP_XOR_WriteProcessMemory_a91d {
  strings:
    $key_a91d = { fe 6f [2] cc 4d [2] ca 78 [2] e4 78 [2] db 64 }

  condition:
    any of them
}