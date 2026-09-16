rule TTP_XOR_WriteProcessMemory_6240 {
  strings:
    $key_6240 = { 35 32 [2] 07 10 [2] 01 25 [2] 2f 25 [2] 10 39 }

  condition:
    any of them
}