rule TTP_XOR_WriteProcessMemory_554d {
  strings:
    $key_554d = { 02 3f [2] 30 1d [2] 36 28 [2] 18 28 [2] 27 34 }

  condition:
    any of them
}