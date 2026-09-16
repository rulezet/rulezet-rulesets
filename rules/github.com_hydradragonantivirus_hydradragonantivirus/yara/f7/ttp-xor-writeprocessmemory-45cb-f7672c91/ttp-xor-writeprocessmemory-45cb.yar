rule TTP_XOR_WriteProcessMemory_45cb {
  strings:
    $key_45cb = { 12 b9 [2] 20 9b [2] 26 ae [2] 08 ae [2] 37 b2 }

  condition:
    any of them
}