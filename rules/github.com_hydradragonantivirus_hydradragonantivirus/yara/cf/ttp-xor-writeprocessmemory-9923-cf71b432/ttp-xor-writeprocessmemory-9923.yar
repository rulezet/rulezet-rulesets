rule TTP_XOR_WriteProcessMemory_9923 {
  strings:
    $key_9923 = { ce 51 [2] fc 73 [2] fa 46 [2] d4 46 [2] eb 5a }

  condition:
    any of them
}