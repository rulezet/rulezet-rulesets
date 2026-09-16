rule TTP_XOR_WriteProcessMemory_8336 {
  strings:
    $key_8336 = { d4 44 [2] e6 66 [2] e0 53 [2] ce 53 [2] f1 4f }

  condition:
    any of them
}