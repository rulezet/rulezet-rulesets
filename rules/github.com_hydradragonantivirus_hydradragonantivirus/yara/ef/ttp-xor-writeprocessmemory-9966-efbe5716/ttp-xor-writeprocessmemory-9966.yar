rule TTP_XOR_WriteProcessMemory_9966 {
  strings:
    $key_9966 = { ce 14 [2] fc 36 [2] fa 03 [2] d4 03 [2] eb 1f }

  condition:
    any of them
}