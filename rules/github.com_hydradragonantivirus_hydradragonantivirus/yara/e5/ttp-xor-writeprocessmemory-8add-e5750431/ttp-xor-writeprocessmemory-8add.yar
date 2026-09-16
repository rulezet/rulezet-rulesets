rule TTP_XOR_WriteProcessMemory_8add {
  strings:
    $key_8add = { dd af [2] ef 8d [2] e9 b8 [2] c7 b8 [2] f8 a4 }

  condition:
    any of them
}