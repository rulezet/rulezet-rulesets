rule TTP_XOR_WriteProcessMemory_775d {
  strings:
    $key_775d = { 20 2f [2] 12 0d [2] 14 38 [2] 3a 38 [2] 05 24 }

  condition:
    any of them
}