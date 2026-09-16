rule TTP_XOR_WriteProcessMemory_ab57 {
  strings:
    $key_ab57 = { fc 25 [2] ce 07 [2] c8 32 [2] e6 32 [2] d9 2e }

  condition:
    any of them
}