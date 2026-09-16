rule TTP_XOR_WriteProcessMemory_22f1 {
  strings:
    $key_22f1 = { 75 83 [2] 47 a1 [2] 41 94 [2] 6f 94 [2] 50 88 }

  condition:
    any of them
}