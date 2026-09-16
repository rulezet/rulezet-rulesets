rule TTP_XOR_WriteProcessMemory_7bb2 {
  strings:
    $key_7bb2 = { 2c c0 [2] 1e e2 [2] 18 d7 [2] 36 d7 [2] 09 cb }

  condition:
    any of them
}