rule TTP_XOR_WriteProcessMemory_0e10 {
  strings:
    $key_0e10 = { 59 62 [2] 6b 40 [2] 6d 75 [2] 43 75 [2] 7c 69 }

  condition:
    any of them
}