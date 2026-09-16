rule TTP_XOR_WriteProcessMemory_abf6 {
  strings:
    $key_abf6 = { fc 84 [2] ce a6 [2] c8 93 [2] e6 93 [2] d9 8f }

  condition:
    any of them
}