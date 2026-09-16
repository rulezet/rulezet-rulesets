rule TTP_XOR_WriteProcessMemory_5d21 {
  strings:
    $key_5d21 = { 0a 53 [2] 38 71 [2] 3e 44 [2] 10 44 [2] 2f 58 }

  condition:
    any of them
}