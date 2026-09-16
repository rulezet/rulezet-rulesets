rule TTP_XOR_WriteProcessMemory_d768 {
  strings:
    $key_d768 = { 80 1a [2] b2 38 [2] b4 0d [2] 9a 0d [2] a5 11 }

  condition:
    any of them
}