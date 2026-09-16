rule TTP_XOR_WriteProcessMemory_9975 {
  strings:
    $key_9975 = { ce 07 [2] fc 25 [2] fa 10 [2] d4 10 [2] eb 0c }

  condition:
    any of them
}