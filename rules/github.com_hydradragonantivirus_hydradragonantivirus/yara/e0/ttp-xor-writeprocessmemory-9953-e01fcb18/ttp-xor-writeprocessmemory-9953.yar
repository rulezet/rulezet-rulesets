rule TTP_XOR_WriteProcessMemory_9953 {
  strings:
    $key_9953 = { ce 21 [2] fc 03 [2] fa 36 [2] d4 36 [2] eb 2a }

  condition:
    any of them
}