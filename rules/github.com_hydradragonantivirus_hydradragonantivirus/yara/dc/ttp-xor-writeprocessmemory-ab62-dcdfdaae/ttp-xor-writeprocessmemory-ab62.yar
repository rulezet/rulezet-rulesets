rule TTP_XOR_WriteProcessMemory_ab62 {
  strings:
    $key_ab62 = { fc 10 [2] ce 32 [2] c8 07 [2] e6 07 [2] d9 1b }

  condition:
    any of them
}