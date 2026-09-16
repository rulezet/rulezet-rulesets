rule TTP_XOR_WriteProcessMemory_bcf0 {
  strings:
    $key_bcf0 = { eb 82 [2] d9 a0 [2] df 95 [2] f1 95 [2] ce 89 }

  condition:
    any of them
}