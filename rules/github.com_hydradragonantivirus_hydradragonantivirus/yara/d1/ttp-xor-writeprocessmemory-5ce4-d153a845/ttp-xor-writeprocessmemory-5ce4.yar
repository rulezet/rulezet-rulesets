rule TTP_XOR_WriteProcessMemory_5ce4 {
  strings:
    $key_5ce4 = { 0b 96 [2] 39 b4 [2] 3f 81 [2] 11 81 [2] 2e 9d }

  condition:
    any of them
}