rule TTP_XOR_WriteProcessMemory_d7dc {
  strings:
    $key_d7dc = { 80 ae [2] b2 8c [2] b4 b9 [2] 9a b9 [2] a5 a5 }

  condition:
    any of them
}