rule TTP_XOR_WriteProcessMemory_2177 {
  strings:
    $key_2177 = { 76 05 [2] 44 27 [2] 42 12 [2] 6c 12 [2] 53 0e }

  condition:
    any of them
}