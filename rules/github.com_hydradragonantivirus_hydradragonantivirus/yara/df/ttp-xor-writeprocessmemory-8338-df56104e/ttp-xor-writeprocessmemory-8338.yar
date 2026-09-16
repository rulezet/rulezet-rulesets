rule TTP_XOR_WriteProcessMemory_8338 {
  strings:
    $key_8338 = { d4 4a [2] e6 68 [2] e0 5d [2] ce 5d [2] f1 41 }

  condition:
    any of them
}