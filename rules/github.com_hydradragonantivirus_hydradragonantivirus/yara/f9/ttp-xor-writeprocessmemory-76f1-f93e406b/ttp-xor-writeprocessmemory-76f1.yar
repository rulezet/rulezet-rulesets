rule TTP_XOR_WriteProcessMemory_76f1 {
  strings:
    $key_76f1 = { 21 83 [2] 13 a1 [2] 15 94 [2] 3b 94 [2] 04 88 }

  condition:
    any of them
}