rule TTP_XOR_WriteProcessMemory_2153 {
  strings:
    $key_2153 = { 76 21 [2] 44 03 [2] 42 36 [2] 6c 36 [2] 53 2a }

  condition:
    any of them
}