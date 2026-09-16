rule TTP_XOR_WriteProcessMemory_e8cb {
  strings:
    $key_e8cb = { bf b9 [2] 8d 9b [2] 8b ae [2] a5 ae [2] 9a b2 }

  condition:
    any of them
}