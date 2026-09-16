rule TTP_XOR_WriteProcessMemory_aaf8 {
  strings:
    $key_aaf8 = { fd 8a [2] cf a8 [2] c9 9d [2] e7 9d [2] d8 81 }

  condition:
    any of them
}