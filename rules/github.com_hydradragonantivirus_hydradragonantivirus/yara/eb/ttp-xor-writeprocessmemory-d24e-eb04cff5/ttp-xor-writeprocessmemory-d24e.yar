rule TTP_XOR_WriteProcessMemory_d24e {
  strings:
    $key_d24e = { 85 3c [2] b7 1e [2] b1 2b [2] 9f 2b [2] a0 37 }

  condition:
    any of them
}