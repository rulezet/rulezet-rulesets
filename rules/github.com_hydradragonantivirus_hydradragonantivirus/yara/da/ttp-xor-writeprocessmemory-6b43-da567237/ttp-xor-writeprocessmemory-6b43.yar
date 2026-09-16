rule TTP_XOR_WriteProcessMemory_6b43 {
  strings:
    $key_6b43 = { 3c 31 [2] 0e 13 [2] 08 26 [2] 26 26 [2] 19 3a }

  condition:
    any of them
}