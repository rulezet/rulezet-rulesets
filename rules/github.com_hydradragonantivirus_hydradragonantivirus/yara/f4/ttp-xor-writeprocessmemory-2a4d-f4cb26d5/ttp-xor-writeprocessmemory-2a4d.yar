rule TTP_XOR_WriteProcessMemory_2a4d {
  strings:
    $key_2a4d = { 7d 3f [2] 4f 1d [2] 49 28 [2] 67 28 [2] 58 34 }

  condition:
    any of them
}