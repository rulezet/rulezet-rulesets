rule TTP_XOR_WriteProcessMemory_8333 {
  strings:
    $key_8333 = { d4 41 [2] e6 63 [2] e0 56 [2] ce 56 [2] f1 4a }

  condition:
    any of them
}