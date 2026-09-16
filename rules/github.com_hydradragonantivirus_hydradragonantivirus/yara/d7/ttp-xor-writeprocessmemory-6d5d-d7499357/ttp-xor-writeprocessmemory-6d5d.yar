rule TTP_XOR_WriteProcessMemory_6d5d {
  strings:
    $key_6d5d = { 3a 2f [2] 08 0d [2] 0e 38 [2] 20 38 [2] 1f 24 }

  condition:
    any of them
}