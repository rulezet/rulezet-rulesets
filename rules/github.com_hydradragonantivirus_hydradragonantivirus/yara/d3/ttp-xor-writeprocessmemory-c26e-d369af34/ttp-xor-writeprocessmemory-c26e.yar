rule TTP_XOR_WriteProcessMemory_c26e {
  strings:
    $key_c26e = { 95 1c [2] a7 3e [2] a1 0b [2] 8f 0b [2] b0 17 }

  condition:
    any of them
}