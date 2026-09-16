rule TTP_XOR_WriteProcessMemory_51b3 {
  strings:
    $key_51b3 = { 06 c1 [2] 34 e3 [2] 32 d6 [2] 1c d6 [2] 23 ca }

  condition:
    any of them
}