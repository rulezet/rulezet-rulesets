rule TTP_XOR_WriteProcessMemory_bcf4 {
  strings:
    $key_bcf4 = { eb 86 [2] d9 a4 [2] df 91 [2] f1 91 [2] ce 8d }

  condition:
    any of them
}