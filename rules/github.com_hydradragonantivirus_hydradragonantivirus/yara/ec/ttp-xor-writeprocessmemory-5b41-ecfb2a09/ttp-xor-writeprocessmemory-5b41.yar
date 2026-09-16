rule TTP_XOR_WriteProcessMemory_5b41 {
  strings:
    $key_5b41 = { 0c 33 [2] 3e 11 [2] 38 24 [2] 16 24 [2] 29 38 }

  condition:
    any of them
}