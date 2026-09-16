rule TTP_XOR_WriteProcessMemory_0b0d {
  strings:
    $key_0b0d = { 5c 7f [2] 6e 5d [2] 68 68 [2] 46 68 [2] 79 74 }

  condition:
    any of them
}