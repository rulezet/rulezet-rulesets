rule TTP_XOR_WriteProcessMemory_1726 {
  strings:
    $key_1726 = { 40 54 [2] 72 76 [2] 74 43 [2] 5a 43 [2] 65 5f }

  condition:
    any of them
}