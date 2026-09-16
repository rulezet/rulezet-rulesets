rule TTP_XOR_WriteProcessMemory_c45c {
  strings:
    $key_c45c = { 93 2e [2] a1 0c [2] a7 39 [2] 89 39 [2] b6 25 }

  condition:
    any of them
}