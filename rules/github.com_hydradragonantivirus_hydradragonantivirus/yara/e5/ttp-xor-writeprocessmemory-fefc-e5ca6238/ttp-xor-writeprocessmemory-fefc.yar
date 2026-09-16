rule TTP_XOR_WriteProcessMemory_fefc {
  strings:
    $key_fefc = { a9 8e [2] 9b ac [2] 9d 99 [2] b3 99 [2] 8c 85 }

  condition:
    any of them
}