rule TTP_XOR_WriteProcessMemory_b3dc {
  strings:
    $key_b3dc = { e4 ae [2] d6 8c [2] d0 b9 [2] fe b9 [2] c1 a5 }

  condition:
    any of them
}