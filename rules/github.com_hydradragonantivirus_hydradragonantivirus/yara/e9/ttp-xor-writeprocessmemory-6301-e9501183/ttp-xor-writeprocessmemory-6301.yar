rule TTP_XOR_WriteProcessMemory_6301 {
  strings:
    $key_6301 = { 34 73 [2] 06 51 [2] 00 64 [2] 2e 64 [2] 11 78 }

  condition:
    any of them
}