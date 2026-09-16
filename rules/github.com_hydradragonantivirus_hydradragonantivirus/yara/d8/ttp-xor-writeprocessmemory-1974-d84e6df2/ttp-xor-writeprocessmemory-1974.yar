rule TTP_XOR_WriteProcessMemory_1974 {
  strings:
    $key_1974 = { 4e 06 [2] 7c 24 [2] 7a 11 [2] 54 11 [2] 6b 0d }

  condition:
    any of them
}