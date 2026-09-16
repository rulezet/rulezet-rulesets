rule TTP_XOR_WriteProcessMemory_c11b {
  strings:
    $key_c11b = { 96 69 [2] a4 4b [2] a2 7e [2] 8c 7e [2] b3 62 }

  condition:
    any of them
}