rule TTP_XOR_WriteProcessMemory_e9cb {
  strings:
    $key_e9cb = { be b9 [2] 8c 9b [2] 8a ae [2] a4 ae [2] 9b b2 }

  condition:
    any of them
}