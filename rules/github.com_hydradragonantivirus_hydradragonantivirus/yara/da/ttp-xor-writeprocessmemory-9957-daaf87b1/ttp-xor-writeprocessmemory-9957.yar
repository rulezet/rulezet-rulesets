rule TTP_XOR_WriteProcessMemory_9957 {
  strings:
    $key_9957 = { ce 25 [2] fc 07 [2] fa 32 [2] d4 32 [2] eb 2e }

  condition:
    any of them
}