rule TTP_XOR_WriteProcessMemory_c1dc {
  strings:
    $key_c1dc = { 96 ae [2] a4 8c [2] a2 b9 [2] 8c b9 [2] b3 a5 }

  condition:
    any of them
}