rule TTP_XOR_WriteProcessMemory_ab07 {
  strings:
    $key_ab07 = { fc 75 [2] ce 57 [2] c8 62 [2] e6 62 [2] d9 7e }

  condition:
    any of them
}