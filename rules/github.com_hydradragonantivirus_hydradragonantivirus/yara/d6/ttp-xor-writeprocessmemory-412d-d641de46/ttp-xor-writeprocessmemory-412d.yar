rule TTP_XOR_WriteProcessMemory_412d {
  strings:
    $key_412d = { 16 5f [2] 24 7d [2] 22 48 [2] 0c 48 [2] 33 54 }

  condition:
    any of them
}