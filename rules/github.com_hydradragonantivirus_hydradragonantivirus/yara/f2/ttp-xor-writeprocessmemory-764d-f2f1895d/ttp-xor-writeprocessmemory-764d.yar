rule TTP_XOR_WriteProcessMemory_764d {
  strings:
    $key_764d = { 21 3f [2] 13 1d [2] 15 28 [2] 3b 28 [2] 04 34 }

  condition:
    any of them
}