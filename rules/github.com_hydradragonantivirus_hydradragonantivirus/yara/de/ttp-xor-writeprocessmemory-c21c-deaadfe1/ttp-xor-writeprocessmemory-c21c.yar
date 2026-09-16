rule TTP_XOR_WriteProcessMemory_c21c {
  strings:
    $key_c21c = { 95 6e [2] a7 4c [2] a1 79 [2] 8f 79 [2] b0 65 }

  condition:
    any of them
}