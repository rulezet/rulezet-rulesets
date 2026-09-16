rule TTP_XOR_WriteProcessMemory_27e4 {
  strings:
    $key_27e4 = { 70 96 [2] 42 b4 [2] 44 81 [2] 6a 81 [2] 55 9d }

  condition:
    any of them
}