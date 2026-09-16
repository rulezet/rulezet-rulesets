rule TTP_XOR_WriteProcessMemory_e7e4 {
  strings:
    $key_e7e4 = { b0 96 [2] 82 b4 [2] 84 81 [2] aa 81 [2] 95 9d }

  condition:
    any of them
}