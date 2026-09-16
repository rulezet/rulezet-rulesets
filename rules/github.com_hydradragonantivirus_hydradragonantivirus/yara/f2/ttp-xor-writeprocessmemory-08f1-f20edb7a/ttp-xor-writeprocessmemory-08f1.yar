rule TTP_XOR_WriteProcessMemory_08f1 {
  strings:
    $key_08f1 = { 5f 83 [2] 6d a1 [2] 6b 94 [2] 45 94 [2] 7a 88 }

  condition:
    any of them
}