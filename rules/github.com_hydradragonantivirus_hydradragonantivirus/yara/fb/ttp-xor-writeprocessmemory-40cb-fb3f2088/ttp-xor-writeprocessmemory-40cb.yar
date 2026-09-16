rule TTP_XOR_WriteProcessMemory_40cb {
  strings:
    $key_40cb = { 17 b9 [2] 25 9b [2] 23 ae [2] 0d ae [2] 32 b2 }

  condition:
    any of them
}