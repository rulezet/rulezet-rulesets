rule TTP_XOR_WriteProcessMemory_aae7 {
  strings:
    $key_aae7 = { fd 95 [2] cf b7 [2] c9 82 [2] e7 82 [2] d8 9e }

  condition:
    any of them
}