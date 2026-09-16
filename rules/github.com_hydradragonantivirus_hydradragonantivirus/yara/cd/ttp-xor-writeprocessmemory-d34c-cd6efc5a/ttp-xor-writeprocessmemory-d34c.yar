rule TTP_XOR_WriteProcessMemory_d34c {
  strings:
    $key_d34c = { 84 3e [2] b6 1c [2] b0 29 [2] 9e 29 [2] a1 35 }

  condition:
    any of them
}