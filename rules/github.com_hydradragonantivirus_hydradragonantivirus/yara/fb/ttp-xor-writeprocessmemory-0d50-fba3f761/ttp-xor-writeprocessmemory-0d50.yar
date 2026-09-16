rule TTP_XOR_WriteProcessMemory_0d50 {
  strings:
    $key_0d50 = { 5a 22 [2] 68 00 [2] 6e 35 [2] 40 35 [2] 7f 29 }

  condition:
    any of them
}