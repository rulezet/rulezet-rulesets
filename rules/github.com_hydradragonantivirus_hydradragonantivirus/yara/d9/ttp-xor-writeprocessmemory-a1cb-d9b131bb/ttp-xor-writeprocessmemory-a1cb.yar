rule TTP_XOR_WriteProcessMemory_a1cb {
  strings:
    $key_a1cb = { f6 b9 [2] c4 9b [2] c2 ae [2] ec ae [2] d3 b2 }

  condition:
    any of them
}