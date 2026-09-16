rule TTP_XOR_WriteProcessMemory_9990 {
  strings:
    $key_9990 = { ce e2 [2] fc c0 [2] fa f5 [2] d4 f5 [2] eb e9 }

  condition:
    any of them
}