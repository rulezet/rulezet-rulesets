rule TTP_XOR_WriteProcessMemory_8371 {
  strings:
    $key_8371 = { d4 03 [2] e6 21 [2] e0 14 [2] ce 14 [2] f1 08 }

  condition:
    any of them
}