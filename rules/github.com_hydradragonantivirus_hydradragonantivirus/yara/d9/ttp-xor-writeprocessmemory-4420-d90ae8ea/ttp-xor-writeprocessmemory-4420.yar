rule TTP_XOR_WriteProcessMemory_4420 {
  strings:
    $key_4420 = { 13 52 [2] 21 70 [2] 27 45 [2] 09 45 [2] 36 59 }

  condition:
    any of them
}