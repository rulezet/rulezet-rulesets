rule TTP_XOR_WriteProcessMemory_61cb {
  strings:
    $key_61cb = { 36 b9 [2] 04 9b [2] 02 ae [2] 2c ae [2] 13 b2 }

  condition:
    any of them
}