rule TTP_XOR_WriteProcessMemory_434d {
  strings:
    $key_434d = { 14 3f [2] 26 1d [2] 20 28 [2] 0e 28 [2] 31 34 }

  condition:
    any of them
}