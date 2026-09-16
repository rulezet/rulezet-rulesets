rule TTP_XOR_WriteProcessMemory_14e4 {
  strings:
    $key_14e4 = { 43 96 [2] 71 b4 [2] 77 81 [2] 59 81 [2] 66 9d }

  condition:
    any of them
}