rule TTP_XOR_WriteProcessMemory_bc53 {
  strings:
    $key_bc53 = { eb 21 [2] d9 03 [2] df 36 [2] f1 36 [2] ce 2a }

  condition:
    any of them
}