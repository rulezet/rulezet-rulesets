rule TTP_XOR_WriteProcessMemory_e9dc {
  strings:
    $key_e9dc = { be ae [2] 8c 8c [2] 8a b9 [2] a4 b9 [2] 9b a5 }

  condition:
    any of them
}