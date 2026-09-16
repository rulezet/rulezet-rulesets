rule TTP_XOR_WriteProcessMemory_d65c {
  strings:
    $key_d65c = { 81 2e [2] b3 0c [2] b5 39 [2] 9b 39 [2] a4 25 }

  condition:
    any of them
}