rule TTP_XOR_WriteProcessMemory_5bf1 {
  strings:
    $key_5bf1 = { 0c 83 [2] 3e a1 [2] 38 94 [2] 16 94 [2] 29 88 }

  condition:
    any of them
}