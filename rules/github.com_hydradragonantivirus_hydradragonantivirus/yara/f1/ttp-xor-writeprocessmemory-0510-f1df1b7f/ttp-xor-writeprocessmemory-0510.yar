rule TTP_XOR_WriteProcessMemory_0510 {
  strings:
    $key_0510 = { 52 62 [2] 60 40 [2] 66 75 [2] 48 75 [2] 77 69 }

  condition:
    any of them
}