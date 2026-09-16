rule TTP_XOR_WriteProcessMemory_3bb2 {
  strings:
    $key_3bb2 = { 6c c0 [2] 5e e2 [2] 58 d7 [2] 76 d7 [2] 49 cb }

  condition:
    any of them
}