rule TTP_XOR_WriteProcessMemory_37f1 {
  strings:
    $key_37f1 = { 60 83 [2] 52 a1 [2] 54 94 [2] 7a 94 [2] 45 88 }

  condition:
    any of them
}