rule TTP_XOR_WriteProcessMemory_d60b {
  strings:
    $key_d60b = { 81 79 [2] b3 5b [2] b5 6e [2] 9b 6e [2] a4 72 }

  condition:
    any of them
}