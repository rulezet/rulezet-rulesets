rule TTP_XOR_WriteProcessMemory_ab2c {
  strings:
    $key_ab2c = { fc 5e [2] ce 7c [2] c8 49 [2] e6 49 [2] d9 55 }

  condition:
    any of them
}