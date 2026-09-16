rule TTP_XOR_WriteProcessMemory_c15e {
  strings:
    $key_c15e = { 96 2c [2] a4 0e [2] a2 3b [2] 8c 3b [2] b3 27 }

  condition:
    any of them
}