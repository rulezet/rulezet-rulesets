rule TTP_XOR_WriteProcessMemory_a4dc {
  strings:
    $key_a4dc = { f3 ae [2] c1 8c [2] c7 b9 [2] e9 b9 [2] d6 a5 }

  condition:
    any of them
}