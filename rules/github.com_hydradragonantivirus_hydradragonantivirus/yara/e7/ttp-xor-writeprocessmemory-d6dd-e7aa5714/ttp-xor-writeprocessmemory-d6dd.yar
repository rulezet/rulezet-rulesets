rule TTP_XOR_WriteProcessMemory_d6dd {
  strings:
    $key_d6dd = { 81 af [2] b3 8d [2] b5 b8 [2] 9b b8 [2] a4 a4 }

  condition:
    any of them
}