rule TTP_XOR_WriteProcessMemory_3972 {
  strings:
    $key_3972 = { 6e 00 [2] 5c 22 [2] 5a 17 [2] 74 17 [2] 4b 0b }

  condition:
    any of them
}