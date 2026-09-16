rule TTP_XOR_WriteProcessMemory_6250 {
  strings:
    $key_6250 = { 35 22 [2] 07 00 [2] 01 35 [2] 2f 35 [2] 10 29 }

  condition:
    any of them
}