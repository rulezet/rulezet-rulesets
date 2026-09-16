rule TTP_XOR_WriteProcessMemory_d09c {
  strings:
    $key_d09c = { 87 ee [2] b5 cc [2] b3 f9 [2] 9d f9 [2] a2 e5 }

  condition:
    any of them
}