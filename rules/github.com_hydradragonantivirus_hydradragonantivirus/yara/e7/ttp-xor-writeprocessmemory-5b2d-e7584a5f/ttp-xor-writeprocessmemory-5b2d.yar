rule TTP_XOR_WriteProcessMemory_5b2d {
  strings:
    $key_5b2d = { 0c 5f [2] 3e 7d [2] 38 48 [2] 16 48 [2] 29 54 }

  condition:
    any of them
}