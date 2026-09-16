rule TTP_XOR_WriteProcessMemory_abc8 {
  strings:
    $key_abc8 = { fc ba [2] ce 98 [2] c8 ad [2] e6 ad [2] d9 b1 }

  condition:
    any of them
}