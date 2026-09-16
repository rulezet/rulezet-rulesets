rule TTP_XOR_WriteProcessMemory_9910 {
  strings:
    $key_9910 = { ce 62 [2] fc 40 [2] fa 75 [2] d4 75 [2] eb 69 }

  condition:
    any of them
}