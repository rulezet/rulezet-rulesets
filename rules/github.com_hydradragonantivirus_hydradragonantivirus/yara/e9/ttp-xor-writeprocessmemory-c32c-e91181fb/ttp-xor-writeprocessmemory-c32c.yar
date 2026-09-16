rule TTP_XOR_WriteProcessMemory_c32c {
  strings:
    $key_c32c = { 94 5e [2] a6 7c [2] a0 49 [2] 8e 49 [2] b1 55 }

  condition:
    any of them
}