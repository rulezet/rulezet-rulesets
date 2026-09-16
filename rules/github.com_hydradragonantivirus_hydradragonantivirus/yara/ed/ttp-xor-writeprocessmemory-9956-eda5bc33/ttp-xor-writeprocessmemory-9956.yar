rule TTP_XOR_WriteProcessMemory_9956 {
  strings:
    $key_9956 = { ce 24 [2] fc 06 [2] fa 33 [2] d4 33 [2] eb 2f }

  condition:
    any of them
}