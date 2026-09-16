rule TTP_XOR_WriteProcessMemory_635d {
  strings:
    $key_635d = { 34 2f [2] 06 0d [2] 00 38 [2] 2e 38 [2] 11 24 }

  condition:
    any of them
}