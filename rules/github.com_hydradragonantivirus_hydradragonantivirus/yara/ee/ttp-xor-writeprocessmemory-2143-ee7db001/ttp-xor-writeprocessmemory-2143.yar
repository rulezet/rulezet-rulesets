rule TTP_XOR_WriteProcessMemory_2143 {
  strings:
    $key_2143 = { 76 31 [2] 44 13 [2] 42 26 [2] 6c 26 [2] 53 3a }

  condition:
    any of them
}