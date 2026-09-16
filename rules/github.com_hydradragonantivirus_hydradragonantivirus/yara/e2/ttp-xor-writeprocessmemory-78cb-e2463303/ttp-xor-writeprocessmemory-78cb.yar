rule TTP_XOR_WriteProcessMemory_78cb {
  strings:
    $key_78cb = { 2f b9 [2] 1d 9b [2] 1b ae [2] 35 ae [2] 0a b2 }

  condition:
    any of them
}