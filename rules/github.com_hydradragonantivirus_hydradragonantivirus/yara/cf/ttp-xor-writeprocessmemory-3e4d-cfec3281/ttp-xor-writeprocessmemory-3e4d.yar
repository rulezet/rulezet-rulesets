rule TTP_XOR_WriteProcessMemory_3e4d {
  strings:
    $key_3e4d = { 69 3f [2] 5b 1d [2] 5d 28 [2] 73 28 [2] 4c 34 }

  condition:
    any of them
}