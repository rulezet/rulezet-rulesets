rule TTP_XOR_WriteProcessMemory_c76e {
  strings:
    $key_c76e = { 90 1c [2] a2 3e [2] a4 0b [2] 8a 0b [2] b5 17 }

  condition:
    any of them
}