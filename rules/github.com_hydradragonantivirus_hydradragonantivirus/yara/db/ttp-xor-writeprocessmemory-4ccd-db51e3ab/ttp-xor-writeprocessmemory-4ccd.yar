rule TTP_XOR_WriteProcessMemory_4ccd {
  strings:
    $key_4ccd = { 1b bf [2] 29 9d [2] 2f a8 [2] 01 a8 [2] 3e b4 }

  condition:
    any of them
}