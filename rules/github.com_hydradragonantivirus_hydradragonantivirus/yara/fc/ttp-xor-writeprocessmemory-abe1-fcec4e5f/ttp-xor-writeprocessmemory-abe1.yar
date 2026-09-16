rule TTP_XOR_WriteProcessMemory_abe1 {
  strings:
    $key_abe1 = { fc 93 [2] ce b1 [2] c8 84 [2] e6 84 [2] d9 98 }

  condition:
    any of them
}