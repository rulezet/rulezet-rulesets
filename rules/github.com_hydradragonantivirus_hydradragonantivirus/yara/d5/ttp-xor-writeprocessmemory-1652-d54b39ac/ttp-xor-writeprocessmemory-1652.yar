rule TTP_XOR_WriteProcessMemory_1652 {
  strings:
    $key_1652 = { 41 20 [2] 73 02 [2] 75 37 [2] 5b 37 [2] 64 2b }

  condition:
    any of them
}