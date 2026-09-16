rule TTP_XOR_WriteProcessMemory_d47e {
  strings:
    $key_d47e = { 83 0c [2] b1 2e [2] b7 1b [2] 99 1b [2] a6 07 }

  condition:
    any of them
}