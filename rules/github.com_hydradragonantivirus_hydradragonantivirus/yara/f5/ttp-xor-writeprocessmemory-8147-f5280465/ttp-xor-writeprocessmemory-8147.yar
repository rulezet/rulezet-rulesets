rule TTP_XOR_WriteProcessMemory_8147 {
  strings:
    $key_8147 = { d6 35 [2] e4 17 [2] e2 22 [2] cc 22 [2] f3 3e }

  condition:
    any of them
}