rule TTP_XOR_WriteProcessMemory_aae3 {
  strings:
    $key_aae3 = { fd 91 [2] cf b3 [2] c9 86 [2] e7 86 [2] d8 9a }

  condition:
    any of them
}