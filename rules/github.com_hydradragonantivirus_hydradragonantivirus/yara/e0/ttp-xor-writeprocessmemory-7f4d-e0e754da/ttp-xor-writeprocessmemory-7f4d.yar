rule TTP_XOR_WriteProcessMemory_7f4d {
  strings:
    $key_7f4d = { 28 3f [2] 1a 1d [2] 1c 28 [2] 32 28 [2] 0d 34 }

  condition:
    any of them
}