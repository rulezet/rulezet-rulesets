rule TTP_XOR_WriteProcessMemory_8347 {
  strings:
    $key_8347 = { d4 35 [2] e6 17 [2] e0 22 [2] ce 22 [2] f1 3e }

  condition:
    any of them
}