rule TTP_XOR_WriteProcessMemory_a4cb {
  strings:
    $key_a4cb = { f3 b9 [2] c1 9b [2] c7 ae [2] e9 ae [2] d6 b2 }

  condition:
    any of them
}