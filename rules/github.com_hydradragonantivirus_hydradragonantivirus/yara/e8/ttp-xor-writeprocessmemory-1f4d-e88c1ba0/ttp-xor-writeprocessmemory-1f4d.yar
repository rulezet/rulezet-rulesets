rule TTP_XOR_WriteProcessMemory_1f4d {
  strings:
    $key_1f4d = { 48 3f [2] 7a 1d [2] 7c 28 [2] 52 28 [2] 6d 34 }

  condition:
    any of them
}