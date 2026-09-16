rule TTP_XOR_WriteProcessMemory_bce6 {
  strings:
    $key_bce6 = { eb 94 [2] d9 b6 [2] df 83 [2] f1 83 [2] ce 9f }

  condition:
    any of them
}