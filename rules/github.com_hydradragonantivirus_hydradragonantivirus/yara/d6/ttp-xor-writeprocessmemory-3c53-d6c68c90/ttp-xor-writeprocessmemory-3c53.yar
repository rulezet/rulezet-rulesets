rule TTP_XOR_WriteProcessMemory_3c53 {
  strings:
    $key_3c53 = { 6b 21 [2] 59 03 [2] 5f 36 [2] 71 36 [2] 4e 2a }

  condition:
    any of them
}