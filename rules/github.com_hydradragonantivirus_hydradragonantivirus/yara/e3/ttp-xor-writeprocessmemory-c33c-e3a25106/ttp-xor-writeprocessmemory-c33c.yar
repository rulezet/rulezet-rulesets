rule TTP_XOR_WriteProcessMemory_c33c {
  strings:
    $key_c33c = { 94 4e [2] a6 6c [2] a0 59 [2] 8e 59 [2] b1 45 }

  condition:
    any of them
}