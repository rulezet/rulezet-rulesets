rule TTP_XOR_WriteProcessMemory_0365 {
  strings:
    $key_0365 = { 54 17 [2] 66 35 [2] 60 00 [2] 4e 00 [2] 71 1c }

  condition:
    any of them
}