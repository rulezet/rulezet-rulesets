rule TTP_XOR_WriteProcessMemory_42cb {
  strings:
    $key_42cb = { 15 b9 [2] 27 9b [2] 21 ae [2] 0f ae [2] 30 b2 }

  condition:
    any of them
}