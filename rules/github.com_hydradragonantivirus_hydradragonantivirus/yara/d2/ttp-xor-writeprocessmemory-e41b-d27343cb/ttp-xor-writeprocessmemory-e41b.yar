rule TTP_XOR_WriteProcessMemory_e41b {
  strings:
    $key_e41b = { b3 69 [2] 81 4b [2] 87 7e [2] a9 7e [2] 96 62 }

  condition:
    any of them
}