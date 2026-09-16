rule TTP_XOR_WriteProcessMemory_7c50 {
  strings:
    $key_7c50 = { 2b 22 [2] 19 00 [2] 1f 35 [2] 31 35 [2] 0e 29 }

  condition:
    any of them
}