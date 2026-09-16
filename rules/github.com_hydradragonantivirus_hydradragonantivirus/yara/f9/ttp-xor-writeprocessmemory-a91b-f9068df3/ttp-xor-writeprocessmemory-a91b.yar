rule TTP_XOR_WriteProcessMemory_a91b {
  strings:
    $key_a91b = { fe 69 [2] cc 4b [2] ca 7e [2] e4 7e [2] db 62 }

  condition:
    any of them
}