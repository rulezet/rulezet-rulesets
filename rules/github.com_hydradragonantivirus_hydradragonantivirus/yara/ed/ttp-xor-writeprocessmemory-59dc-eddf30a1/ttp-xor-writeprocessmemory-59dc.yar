rule TTP_XOR_WriteProcessMemory_59dc {
  strings:
    $key_59dc = { 0e ae [2] 3c 8c [2] 3a b9 [2] 14 b9 [2] 2b a5 }

  condition:
    any of them
}