rule TTP_XOR_WriteProcessMemory_505d {
  strings:
    $key_505d = { 07 2f [2] 35 0d [2] 33 38 [2] 1d 38 [2] 22 24 }

  condition:
    any of them
}