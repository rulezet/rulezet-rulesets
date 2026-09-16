rule TTP_XOR_WriteProcessMemory_7271 {
  strings:
    $key_7271 = { 25 03 [2] 17 21 [2] 11 14 [2] 3f 14 [2] 00 08 }

  condition:
    any of them
}