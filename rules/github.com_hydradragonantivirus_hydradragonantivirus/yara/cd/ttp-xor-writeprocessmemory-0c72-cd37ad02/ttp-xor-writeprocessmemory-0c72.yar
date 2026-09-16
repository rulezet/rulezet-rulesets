rule TTP_XOR_WriteProcessMemory_0c72 {
  strings:
    $key_0c72 = { 5b 00 [2] 69 22 [2] 6f 17 [2] 41 17 [2] 7e 0b }

  condition:
    any of them
}