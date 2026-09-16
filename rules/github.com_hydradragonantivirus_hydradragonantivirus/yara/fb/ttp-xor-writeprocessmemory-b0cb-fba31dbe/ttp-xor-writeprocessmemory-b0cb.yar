rule TTP_XOR_WriteProcessMemory_b0cb {
  strings:
    $key_b0cb = { e7 b9 [2] d5 9b [2] d3 ae [2] fd ae [2] c2 b2 }

  condition:
    any of them
}