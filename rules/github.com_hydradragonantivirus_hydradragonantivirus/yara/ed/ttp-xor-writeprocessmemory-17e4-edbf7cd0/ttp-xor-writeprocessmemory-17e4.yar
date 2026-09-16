rule TTP_XOR_WriteProcessMemory_17e4 {
  strings:
    $key_17e4 = { 40 96 [2] 72 b4 [2] 74 81 [2] 5a 81 [2] 65 9d }

  condition:
    any of them
}