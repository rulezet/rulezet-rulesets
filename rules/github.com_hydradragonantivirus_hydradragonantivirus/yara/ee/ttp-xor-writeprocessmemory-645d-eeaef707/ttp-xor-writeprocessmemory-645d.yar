rule TTP_XOR_WriteProcessMemory_645d {
  strings:
    $key_645d = { 33 2f [2] 01 0d [2] 07 38 [2] 29 38 [2] 16 24 }

  condition:
    any of them
}