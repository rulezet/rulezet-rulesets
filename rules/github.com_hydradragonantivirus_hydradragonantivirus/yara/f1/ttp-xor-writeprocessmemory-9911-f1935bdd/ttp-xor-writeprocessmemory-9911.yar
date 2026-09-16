rule TTP_XOR_WriteProcessMemory_9911 {
  strings:
    $key_9911 = { ce 63 [2] fc 41 [2] fa 74 [2] d4 74 [2] eb 68 }

  condition:
    any of them
}