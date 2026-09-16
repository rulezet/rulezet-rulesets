rule TTP_XOR_WriteProcessMemory_1bb2 {
  strings:
    $key_1bb2 = { 4c c0 [2] 7e e2 [2] 78 d7 [2] 56 d7 [2] 69 cb }

  condition:
    any of them
}