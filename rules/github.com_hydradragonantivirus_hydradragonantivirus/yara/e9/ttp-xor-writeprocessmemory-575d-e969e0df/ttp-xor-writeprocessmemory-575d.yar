rule TTP_XOR_WriteProcessMemory_575d {
  strings:
    $key_575d = { 00 2f [2] 32 0d [2] 34 38 [2] 1a 38 [2] 25 24 }

  condition:
    any of them
}