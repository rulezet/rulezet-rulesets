rule TTP_XOR_WriteProcessMemory_0e51 {
  strings:
    $key_0e51 = { 59 23 [2] 6b 01 [2] 6d 34 [2] 43 34 [2] 7c 28 }

  condition:
    any of them
}