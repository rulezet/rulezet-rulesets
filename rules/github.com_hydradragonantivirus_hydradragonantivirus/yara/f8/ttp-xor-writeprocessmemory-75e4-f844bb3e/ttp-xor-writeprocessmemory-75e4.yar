rule TTP_XOR_WriteProcessMemory_75e4 {
  strings:
    $key_75e4 = { 22 96 [2] 10 b4 [2] 16 81 [2] 38 81 [2] 07 9d }

  condition:
    any of them
}