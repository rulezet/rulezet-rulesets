rule TTP_XOR_WriteProcessMemory_ab48 {
  strings:
    $key_ab48 = { fc 3a [2] ce 18 [2] c8 2d [2] e6 2d [2] d9 31 }

  condition:
    any of them
}