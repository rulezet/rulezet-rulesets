rule TTP_XOR_WriteProcessMemory_6271 {
  strings:
    $key_6271 = { 35 03 [2] 07 21 [2] 01 14 [2] 2f 14 [2] 10 08 }

  condition:
    any of them
}