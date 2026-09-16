rule TTP_XOR_WriteProcessMemory_9920 {
  strings:
    $key_9920 = { ce 52 [2] fc 70 [2] fa 45 [2] d4 45 [2] eb 59 }

  condition:
    any of them
}