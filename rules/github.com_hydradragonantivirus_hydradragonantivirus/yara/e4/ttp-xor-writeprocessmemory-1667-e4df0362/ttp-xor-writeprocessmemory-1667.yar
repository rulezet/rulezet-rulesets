rule TTP_XOR_WriteProcessMemory_1667 {
  strings:
    $key_1667 = { 41 15 [2] 73 37 [2] 75 02 [2] 5b 02 [2] 64 1e }

  condition:
    any of them
}