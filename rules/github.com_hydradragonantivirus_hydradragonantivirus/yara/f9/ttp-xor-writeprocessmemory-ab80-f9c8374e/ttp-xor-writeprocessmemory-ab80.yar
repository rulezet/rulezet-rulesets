rule TTP_XOR_WriteProcessMemory_ab80 {
  strings:
    $key_ab80 = { fc f2 [2] ce d0 [2] c8 e5 [2] e6 e5 [2] d9 f9 }

  condition:
    any of them
}