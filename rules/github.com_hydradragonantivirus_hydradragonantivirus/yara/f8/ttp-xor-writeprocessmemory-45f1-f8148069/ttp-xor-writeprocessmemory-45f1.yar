rule TTP_XOR_WriteProcessMemory_45f1 {
  strings:
    $key_45f1 = { 12 83 [2] 20 a1 [2] 26 94 [2] 08 94 [2] 37 88 }

  condition:
    any of them
}