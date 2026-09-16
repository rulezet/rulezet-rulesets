rule TTP_XOR_WriteProcessMemory_9941 {
  strings:
    $key_9941 = { ce 33 [2] fc 11 [2] fa 24 [2] d4 24 [2] eb 38 }

  condition:
    any of them
}