rule TTP_XOR_WriteProcessMemory_3956 {
  strings:
    $key_3956 = { 6e 24 [2] 5c 06 [2] 5a 33 [2] 74 33 [2] 4b 2f }

  condition:
    any of them
}