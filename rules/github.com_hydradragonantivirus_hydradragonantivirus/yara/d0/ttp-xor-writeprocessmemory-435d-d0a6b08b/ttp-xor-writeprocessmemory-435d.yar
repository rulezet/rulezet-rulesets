rule TTP_XOR_WriteProcessMemory_435d {
  strings:
    $key_435d = { 14 2f [2] 26 0d [2] 20 38 [2] 0e 38 [2] 31 24 }

  condition:
    any of them
}