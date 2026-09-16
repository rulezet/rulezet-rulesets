rule TTP_XOR_WriteProcessMemory_9930 {
  strings:
    $key_9930 = { ce 42 [2] fc 60 [2] fa 55 [2] d4 55 [2] eb 49 }

  condition:
    any of them
}