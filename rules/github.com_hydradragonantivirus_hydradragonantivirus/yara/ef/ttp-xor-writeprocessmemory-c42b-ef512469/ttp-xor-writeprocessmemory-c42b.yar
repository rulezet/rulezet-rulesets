rule TTP_XOR_WriteProcessMemory_c42b {
  strings:
    $key_c42b = { 93 59 [2] a1 7b [2] a7 4e [2] 89 4e [2] b6 52 }

  condition:
    any of them
}