rule TTP_XOR_WriteProcessMemory_ab00 {
  strings:
    $key_ab00 = { fc 72 [2] ce 50 [2] c8 65 [2] e6 65 [2] d9 79 }

  condition:
    any of them
}