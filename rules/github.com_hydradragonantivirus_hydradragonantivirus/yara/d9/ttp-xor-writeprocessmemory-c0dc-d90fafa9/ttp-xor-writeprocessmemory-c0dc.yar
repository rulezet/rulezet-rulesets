rule TTP_XOR_WriteProcessMemory_c0dc {
  strings:
    $key_c0dc = { 97 ae [2] a5 8c [2] a3 b9 [2] 8d b9 [2] b2 a5 }

  condition:
    any of them
}