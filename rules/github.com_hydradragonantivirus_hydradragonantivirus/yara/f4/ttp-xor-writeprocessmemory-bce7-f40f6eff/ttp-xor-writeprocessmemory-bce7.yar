rule TTP_XOR_WriteProcessMemory_bce7 {
  strings:
    $key_bce7 = { eb 95 [2] d9 b7 [2] df 82 [2] f1 82 [2] ce 9e }

  condition:
    any of them
}