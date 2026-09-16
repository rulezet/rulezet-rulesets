rule TTP_XOR_WriteProcessMemory_d0cb {
  strings:
    $key_d0cb = { 87 b9 [2] b5 9b [2] b3 ae [2] 9d ae [2] a2 b2 }

  condition:
    any of them
}