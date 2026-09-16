rule TTP_XOR_WriteProcessMemory_019c {
  strings:
    $key_019c = { 56 ee [2] 64 cc [2] 62 f9 [2] 4c f9 [2] 73 e5 }

  condition:
    any of them
}