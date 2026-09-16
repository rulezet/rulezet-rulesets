rule TTP_XOR_WriteProcessMemory_ab26 {
  strings:
    $key_ab26 = { fc 54 [2] ce 76 [2] c8 43 [2] e6 43 [2] d9 5f }

  condition:
    any of them
}