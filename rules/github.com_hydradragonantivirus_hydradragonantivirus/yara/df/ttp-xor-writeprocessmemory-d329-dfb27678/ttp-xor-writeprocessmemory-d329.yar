rule TTP_XOR_WriteProcessMemory_d329 {
  strings:
    $key_d329 = { 84 5b [2] b6 79 [2] b0 4c [2] 9e 4c [2] a1 50 }

  condition:
    any of them
}