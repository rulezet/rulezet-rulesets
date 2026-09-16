rule TTP_XOR_WriteProcessMemory_c6cb {
  strings:
    $key_c6cb = { 91 b9 [2] a3 9b [2] a5 ae [2] 8b ae [2] b4 b2 }

  condition:
    any of them
}