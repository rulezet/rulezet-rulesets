rule TTP_XOR_WriteProcessMemory_621b {
  strings:
    $key_621b = { 35 69 [2] 07 4b [2] 01 7e [2] 2f 7e [2] 10 62 }

  condition:
    any of them
}