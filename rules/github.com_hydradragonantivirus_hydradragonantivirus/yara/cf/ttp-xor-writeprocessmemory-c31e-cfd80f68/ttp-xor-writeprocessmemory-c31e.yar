rule TTP_XOR_WriteProcessMemory_c31e {
  strings:
    $key_c31e = { 94 6c [2] a6 4e [2] a0 7b [2] 8e 7b [2] b1 67 }

  condition:
    any of them
}