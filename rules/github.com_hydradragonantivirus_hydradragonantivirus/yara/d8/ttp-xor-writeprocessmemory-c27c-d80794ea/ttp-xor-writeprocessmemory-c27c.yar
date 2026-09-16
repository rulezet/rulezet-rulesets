rule TTP_XOR_WriteProcessMemory_c27c {
  strings:
    $key_c27c = { 95 0e [2] a7 2c [2] a1 19 [2] 8f 19 [2] b0 05 }

  condition:
    any of them
}