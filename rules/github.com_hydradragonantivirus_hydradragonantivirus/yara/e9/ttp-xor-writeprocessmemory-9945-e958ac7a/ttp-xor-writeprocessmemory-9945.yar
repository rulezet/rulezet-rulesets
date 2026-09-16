rule TTP_XOR_WriteProcessMemory_9945 {
  strings:
    $key_9945 = { ce 37 [2] fc 15 [2] fa 20 [2] d4 20 [2] eb 3c }

  condition:
    any of them
}