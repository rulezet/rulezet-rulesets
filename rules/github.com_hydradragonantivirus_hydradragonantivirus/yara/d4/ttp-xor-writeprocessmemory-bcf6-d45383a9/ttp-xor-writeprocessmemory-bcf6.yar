rule TTP_XOR_WriteProcessMemory_bcf6 {
  strings:
    $key_bcf6 = { eb 84 [2] d9 a6 [2] df 93 [2] f1 93 [2] ce 8f }

  condition:
    any of them
}