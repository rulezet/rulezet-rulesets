rule TTP_XOR_WriteProcessMemory_6f0d {
  strings:
    $key_6f0d = { 38 7f [2] 0a 5d [2] 0c 68 [2] 22 68 [2] 1d 74 }

  condition:
    any of them
}