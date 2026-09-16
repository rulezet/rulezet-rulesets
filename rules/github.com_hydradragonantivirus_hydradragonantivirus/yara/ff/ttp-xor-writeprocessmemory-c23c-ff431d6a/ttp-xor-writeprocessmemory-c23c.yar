rule TTP_XOR_WriteProcessMemory_c23c {
  strings:
    $key_c23c = { 95 4e [2] a7 6c [2] a1 59 [2] 8f 59 [2] b0 45 }

  condition:
    any of them
}