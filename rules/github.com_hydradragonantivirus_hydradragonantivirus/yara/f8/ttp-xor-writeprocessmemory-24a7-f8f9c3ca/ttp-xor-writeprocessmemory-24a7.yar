rule TTP_XOR_WriteProcessMemory_24a7 {
  strings:
    $key_24a7 = { 73 d5 [2] 41 f7 [2] 47 c2 [2] 69 c2 [2] 56 de }

  condition:
    any of them
}