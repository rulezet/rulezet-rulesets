rule TTP_XOR_WriteProcessMemory_1fac {
  strings:
    $key_1fac = { 48 de [2] 7a fc [2] 7c c9 [2] 52 c9 [2] 6d d5 }

  condition:
    any of them
}