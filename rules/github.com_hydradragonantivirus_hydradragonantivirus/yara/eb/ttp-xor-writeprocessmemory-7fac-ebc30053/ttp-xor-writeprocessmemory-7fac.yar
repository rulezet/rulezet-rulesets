rule TTP_XOR_WriteProcessMemory_7fac {
  strings:
    $key_7fac = { 28 de [2] 1a fc [2] 1c c9 [2] 32 c9 [2] 0d d5 }

  condition:
    any of them
}