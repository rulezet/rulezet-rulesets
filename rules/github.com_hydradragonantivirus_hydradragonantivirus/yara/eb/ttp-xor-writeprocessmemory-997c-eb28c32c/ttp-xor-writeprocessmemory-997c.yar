rule TTP_XOR_WriteProcessMemory_997c {
  strings:
    $key_997c = { ce 0e [2] fc 2c [2] fa 19 [2] d4 19 [2] eb 05 }

  condition:
    any of them
}