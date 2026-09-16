rule TTP_XOR_WriteProcessMemory_abf3 {
  strings:
    $key_abf3 = { fc 81 [2] ce a3 [2] c8 96 [2] e6 96 [2] d9 8a }

  condition:
    any of them
}