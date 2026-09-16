rule TTP_XOR_WriteProcessMemory_0e53 {
  strings:
    $key_0e53 = { 59 21 [2] 6b 03 [2] 6d 36 [2] 43 36 [2] 7c 2a }

  condition:
    any of them
}