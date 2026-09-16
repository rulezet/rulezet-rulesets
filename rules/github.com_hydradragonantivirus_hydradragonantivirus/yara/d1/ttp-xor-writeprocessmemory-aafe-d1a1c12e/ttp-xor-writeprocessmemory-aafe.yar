rule TTP_XOR_WriteProcessMemory_aafe {
  strings:
    $key_aafe = { fd 8c [2] cf ae [2] c9 9b [2] e7 9b [2] d8 87 }

  condition:
    any of them
}