rule TTP_XOR_WriteProcessMemory_ab68 {
  strings:
    $key_ab68 = { fc 1a [2] ce 38 [2] c8 0d [2] e6 0d [2] d9 11 }

  condition:
    any of them
}