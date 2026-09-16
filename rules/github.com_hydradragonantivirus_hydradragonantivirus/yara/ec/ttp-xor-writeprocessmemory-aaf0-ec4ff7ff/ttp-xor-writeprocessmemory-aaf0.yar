rule TTP_XOR_WriteProcessMemory_aaf0 {
  strings:
    $key_aaf0 = { fd 82 [2] cf a0 [2] c9 95 [2] e7 95 [2] d8 89 }

  condition:
    any of them
}