rule TTP_XOR_WriteProcessMemory_6bd3 {
  strings:
    $key_6bd3 = { 3c a1 [2] 0e 83 [2] 08 b6 [2] 26 b6 [2] 19 aa }

  condition:
    any of them
}