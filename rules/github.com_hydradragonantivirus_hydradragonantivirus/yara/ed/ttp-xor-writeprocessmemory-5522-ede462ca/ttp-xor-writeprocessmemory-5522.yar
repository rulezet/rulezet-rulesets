rule TTP_XOR_WriteProcessMemory_5522 {
  strings:
    $key_5522 = { 02 50 [2] 30 72 [2] 36 47 [2] 18 47 [2] 27 5b }

  condition:
    any of them
}