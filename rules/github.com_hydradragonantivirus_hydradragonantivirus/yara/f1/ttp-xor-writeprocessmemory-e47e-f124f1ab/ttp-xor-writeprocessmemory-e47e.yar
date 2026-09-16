rule TTP_XOR_WriteProcessMemory_e47e {
  strings:
    $key_e47e = { b3 0c [2] 81 2e [2] 87 1b [2] a9 1b [2] 96 07 }

  condition:
    any of them
}