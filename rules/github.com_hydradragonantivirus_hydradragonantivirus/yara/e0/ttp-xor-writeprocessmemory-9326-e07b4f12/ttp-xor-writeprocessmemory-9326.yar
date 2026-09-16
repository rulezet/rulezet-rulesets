rule TTP_XOR_WriteProcessMemory_9326 {
  strings:
    $key_9326 = { c4 54 [2] f6 76 [2] f0 43 [2] de 43 [2] e1 5f }

  condition:
    any of them
}