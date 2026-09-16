rule TTP_XOR_WriteProcessMemory_e7cb {
  strings:
    $key_e7cb = { b0 b9 [2] 82 9b [2] 84 ae [2] aa ae [2] 95 b2 }

  condition:
    any of them
}