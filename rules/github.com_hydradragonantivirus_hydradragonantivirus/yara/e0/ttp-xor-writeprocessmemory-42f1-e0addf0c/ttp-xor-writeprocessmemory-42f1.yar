rule TTP_XOR_WriteProcessMemory_42f1 {
  strings:
    $key_42f1 = { 15 83 [2] 27 a1 [2] 21 94 [2] 0f 94 [2] 30 88 }

  condition:
    any of them
}