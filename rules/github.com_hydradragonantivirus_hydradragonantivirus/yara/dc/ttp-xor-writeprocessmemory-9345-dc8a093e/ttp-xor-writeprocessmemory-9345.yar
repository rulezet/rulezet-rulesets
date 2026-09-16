rule TTP_XOR_WriteProcessMemory_9345 {
  strings:
    $key_9345 = { c4 37 [2] f6 15 [2] f0 20 [2] de 20 [2] e1 3c }

  condition:
    any of them
}