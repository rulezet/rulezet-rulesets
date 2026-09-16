rule TTP_XOR_WriteProcessMemory_d7e8 {
  strings:
    $key_d7e8 = { 80 9a [2] b2 b8 [2] b4 8d [2] 9a 8d [2] a5 91 }

  condition:
    any of them
}