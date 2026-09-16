rule TTP_XOR_WriteProcessMemory_8377 {
  strings:
    $key_8377 = { d4 05 [2] e6 27 [2] e0 12 [2] ce 12 [2] f1 0e }

  condition:
    any of them
}