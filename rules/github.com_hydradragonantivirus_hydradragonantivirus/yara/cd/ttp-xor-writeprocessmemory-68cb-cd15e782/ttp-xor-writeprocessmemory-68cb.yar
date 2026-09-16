rule TTP_XOR_WriteProcessMemory_68cb {
  strings:
    $key_68cb = { 3f b9 [2] 0d 9b [2] 0b ae [2] 25 ae [2] 1a b2 }

  condition:
    any of them
}