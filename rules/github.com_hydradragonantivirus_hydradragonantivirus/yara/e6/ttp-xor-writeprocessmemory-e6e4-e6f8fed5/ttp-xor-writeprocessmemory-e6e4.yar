rule TTP_XOR_WriteProcessMemory_e6e4 {
  strings:
    $key_e6e4 = { b1 96 [2] 83 b4 [2] 85 81 [2] ab 81 [2] 94 9d }

  condition:
    any of them
}