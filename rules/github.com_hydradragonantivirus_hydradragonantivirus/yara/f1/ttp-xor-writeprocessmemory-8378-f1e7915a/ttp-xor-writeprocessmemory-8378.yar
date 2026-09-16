rule TTP_XOR_WriteProcessMemory_8378 {
  strings:
    $key_8378 = { d4 0a [2] e6 28 [2] e0 1d [2] ce 1d [2] f1 01 }

  condition:
    any of them
}