rule TTP_XOR_WriteProcessMemory_4a0d {
  strings:
    $key_4a0d = { 1d 7f [2] 2f 5d [2] 29 68 [2] 07 68 [2] 38 74 }

  condition:
    any of them
}