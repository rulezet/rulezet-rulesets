rule TTP_XOR_WriteProcessMemory_8328 {
  strings:
    $key_8328 = { d4 5a [2] e6 78 [2] e0 4d [2] ce 4d [2] f1 51 }

  condition:
    any of them
}