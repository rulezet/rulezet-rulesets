rule TTP_XOR_WriteProcessMemory_ab56 {
  strings:
    $key_ab56 = { fc 24 [2] ce 06 [2] c8 33 [2] e6 33 [2] d9 2f }

  condition:
    any of them
}