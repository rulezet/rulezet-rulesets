rule TTP_XOR_WriteProcessMemory_9908 {
  strings:
    $key_9908 = { ce 7a [2] fc 58 [2] fa 6d [2] d4 6d [2] eb 71 }

  condition:
    any of them
}