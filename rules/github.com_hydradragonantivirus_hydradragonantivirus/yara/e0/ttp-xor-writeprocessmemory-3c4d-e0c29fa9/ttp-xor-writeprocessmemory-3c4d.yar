rule TTP_XOR_WriteProcessMemory_3c4d {
  strings:
    $key_3c4d = { 6b 3f [2] 59 1d [2] 5f 28 [2] 71 28 [2] 4e 34 }

  condition:
    any of them
}