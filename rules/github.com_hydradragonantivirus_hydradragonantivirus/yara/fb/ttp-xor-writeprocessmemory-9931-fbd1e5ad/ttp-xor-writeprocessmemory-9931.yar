rule TTP_XOR_WriteProcessMemory_9931 {
  strings:
    $key_9931 = { ce 43 [2] fc 61 [2] fa 54 [2] d4 54 [2] eb 48 }

  condition:
    any of them
}