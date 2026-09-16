rule TTP_XOR_WriteProcessMemory_7c22 {
  strings:
    $key_7c22 = { 2b 50 [2] 19 72 [2] 1f 47 [2] 31 47 [2] 0e 5b }

  condition:
    any of them
}