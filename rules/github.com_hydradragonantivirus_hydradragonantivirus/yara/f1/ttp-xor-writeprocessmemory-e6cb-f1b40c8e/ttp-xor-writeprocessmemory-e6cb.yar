rule TTP_XOR_WriteProcessMemory_e6cb {
  strings:
    $key_e6cb = { b1 b9 [2] 83 9b [2] 85 ae [2] ab ae [2] 94 b2 }

  condition:
    any of them
}