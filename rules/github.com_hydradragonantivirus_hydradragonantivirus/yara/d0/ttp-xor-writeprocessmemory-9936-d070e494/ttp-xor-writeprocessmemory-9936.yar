rule TTP_XOR_WriteProcessMemory_9936 {
  strings:
    $key_9936 = { ce 44 [2] fc 66 [2] fa 53 [2] d4 53 [2] eb 4f }

  condition:
    any of them
}