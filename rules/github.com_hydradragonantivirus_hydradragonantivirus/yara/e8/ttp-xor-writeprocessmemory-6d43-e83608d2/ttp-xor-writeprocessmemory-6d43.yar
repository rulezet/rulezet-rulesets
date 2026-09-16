rule TTP_XOR_WriteProcessMemory_6d43 {
  strings:
    $key_6d43 = { 3a 31 [2] 08 13 [2] 0e 26 [2] 20 26 [2] 1f 3a }

  condition:
    any of them
}