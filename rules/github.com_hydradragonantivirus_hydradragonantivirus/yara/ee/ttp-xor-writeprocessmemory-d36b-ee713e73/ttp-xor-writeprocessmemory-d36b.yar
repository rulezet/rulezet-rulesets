rule TTP_XOR_WriteProcessMemory_d36b {
  strings:
    $key_d36b = { 84 19 [2] b6 3b [2] b0 0e [2] 9e 0e [2] a1 12 }

  condition:
    any of them
}