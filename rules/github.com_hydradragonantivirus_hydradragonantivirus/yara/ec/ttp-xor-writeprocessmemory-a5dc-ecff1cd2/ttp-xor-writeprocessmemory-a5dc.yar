rule TTP_XOR_WriteProcessMemory_a5dc {
  strings:
    $key_a5dc = { f2 ae [2] c0 8c [2] c6 b9 [2] e8 b9 [2] d7 a5 }

  condition:
    any of them
}