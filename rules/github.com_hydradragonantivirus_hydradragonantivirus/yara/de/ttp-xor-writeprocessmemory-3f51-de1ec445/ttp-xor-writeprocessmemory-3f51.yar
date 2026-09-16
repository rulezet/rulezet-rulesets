rule TTP_XOR_WriteProcessMemory_3f51 {
  strings:
    $key_3f51 = { 68 23 [2] 5a 01 [2] 5c 34 [2] 72 34 [2] 4d 28 }

  condition:
    any of them
}