rule TTP_XOR_WriteProcessMemory_8177 {
  strings:
    $key_8177 = { d6 05 [2] e4 27 [2] e2 12 [2] cc 12 [2] f3 0e }

  condition:
    any of them
}