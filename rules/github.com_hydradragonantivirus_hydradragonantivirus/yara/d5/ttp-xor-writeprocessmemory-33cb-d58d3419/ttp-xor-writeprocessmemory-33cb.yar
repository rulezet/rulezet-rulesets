rule TTP_XOR_WriteProcessMemory_33cb {
  strings:
    $key_33cb = { 64 b9 [2] 56 9b [2] 50 ae [2] 7e ae [2] 41 b2 }

  condition:
    any of them
}