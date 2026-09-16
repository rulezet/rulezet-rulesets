rule TTP_XOR_WriteProcessMemory_35e4 {
  strings:
    $key_35e4 = { 62 96 [2] 50 b4 [2] 56 81 [2] 78 81 [2] 47 9d }

  condition:
    any of them
}