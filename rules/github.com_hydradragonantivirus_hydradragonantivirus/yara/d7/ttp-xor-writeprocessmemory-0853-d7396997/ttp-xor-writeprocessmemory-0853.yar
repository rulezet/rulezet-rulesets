rule TTP_XOR_WriteProcessMemory_0853 {
  strings:
    $key_0853 = { 5f 21 [2] 6d 03 [2] 6b 36 [2] 45 36 [2] 7a 2a }

  condition:
    any of them
}