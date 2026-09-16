rule TTP_XOR_WriteProcessMemory_e5cb {
  strings:
    $key_e5cb = { b2 b9 [2] 80 9b [2] 86 ae [2] a8 ae [2] 97 b2 }

  condition:
    any of them
}