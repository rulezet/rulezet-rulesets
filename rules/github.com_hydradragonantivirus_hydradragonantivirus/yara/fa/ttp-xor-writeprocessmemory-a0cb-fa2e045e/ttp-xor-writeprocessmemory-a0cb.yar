rule TTP_XOR_WriteProcessMemory_a0cb {
  strings:
    $key_a0cb = { f7 b9 [2] c5 9b [2] c3 ae [2] ed ae [2] d2 b2 }

  condition:
    any of them
}