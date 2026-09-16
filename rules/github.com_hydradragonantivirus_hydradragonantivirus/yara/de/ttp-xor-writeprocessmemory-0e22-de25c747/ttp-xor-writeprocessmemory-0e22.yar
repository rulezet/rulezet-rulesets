rule TTP_XOR_WriteProcessMemory_0e22 {
  strings:
    $key_0e22 = { 59 50 [2] 6b 72 [2] 6d 47 [2] 43 47 [2] 7c 5b }

  condition:
    any of them
}