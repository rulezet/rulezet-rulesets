rule TTP_XOR_WriteProcessMemory_9917 {
  strings:
    $key_9917 = { ce 65 [2] fc 47 [2] fa 72 [2] d4 72 [2] eb 6e }

  condition:
    any of them
}