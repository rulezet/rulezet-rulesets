rule TTP_XOR_WriteProcessMemory_44c0 {
  strings:
    $key_44c0 = { 13 b2 [2] 21 90 [2] 27 a5 [2] 09 a5 [2] 36 b9 }

  condition:
    any of them
}