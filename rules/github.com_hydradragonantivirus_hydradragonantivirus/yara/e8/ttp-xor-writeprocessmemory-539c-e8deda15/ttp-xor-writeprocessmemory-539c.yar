rule TTP_XOR_WriteProcessMemory_539c {
  strings:
    $key_539c = { 04 ee [2] 36 cc [2] 30 f9 [2] 1e f9 [2] 21 e5 }

  condition:
    any of them
}