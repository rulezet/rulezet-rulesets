rule TTP_XOR_WriteProcessMemory_0551 {
  strings:
    $key_0551 = { 52 23 [2] 60 01 [2] 66 34 [2] 48 34 [2] 77 28 }

  condition:
    any of them
}