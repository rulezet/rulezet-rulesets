rule TTP_XOR_WriteProcessMemory_ab40 {
  strings:
    $key_ab40 = { fc 32 [2] ce 10 [2] c8 25 [2] e6 25 [2] d9 39 }

  condition:
    any of them
}