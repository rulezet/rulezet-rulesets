rule TTP_XOR_WriteProcessMemory_6b02 {
  strings:
    $key_6b02 = { 3c 70 [2] 0e 52 [2] 08 67 [2] 26 67 [2] 19 7b }

  condition:
    any of them
}