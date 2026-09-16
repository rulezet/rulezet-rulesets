rule TTP_XOR_WriteProcessMemory_9951 {
  strings:
    $key_9951 = { ce 23 [2] fc 01 [2] fa 34 [2] d4 34 [2] eb 28 }

  condition:
    any of them
}