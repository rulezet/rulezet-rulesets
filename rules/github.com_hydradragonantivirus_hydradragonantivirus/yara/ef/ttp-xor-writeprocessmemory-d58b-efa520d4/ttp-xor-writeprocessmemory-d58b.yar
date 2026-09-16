rule TTP_XOR_WriteProcessMemory_d58b {
  strings:
    $key_d58b = { 82 f9 [2] b0 db [2] b6 ee [2] 98 ee [2] a7 f2 }

  condition:
    any of them
}