rule TTP_XOR_WriteProcessMemory_1964 {
  strings:
    $key_1964 = { 4e 16 [2] 7c 34 [2] 7a 01 [2] 54 01 [2] 6b 1d }

  condition:
    any of them
}