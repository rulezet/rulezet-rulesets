rule TTP_XOR_WriteProcessMemory_c32e {
  strings:
    $key_c32e = { 94 5c [2] a6 7e [2] a0 4b [2] 8e 4b [2] b1 57 }

  condition:
    any of them
}