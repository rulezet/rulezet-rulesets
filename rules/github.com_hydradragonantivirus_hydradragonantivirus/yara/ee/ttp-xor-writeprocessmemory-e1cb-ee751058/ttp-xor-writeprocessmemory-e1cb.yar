rule TTP_XOR_WriteProcessMemory_e1cb {
  strings:
    $key_e1cb = { b6 b9 [2] 84 9b [2] 82 ae [2] ac ae [2] 93 b2 }

  condition:
    any of them
}