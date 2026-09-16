rule TTP_XOR_WriteProcessMemory_c329 {
  strings:
    $key_c329 = { 94 5b [2] a6 79 [2] a0 4c [2] 8e 4c [2] b1 50 }

  condition:
    any of them
}