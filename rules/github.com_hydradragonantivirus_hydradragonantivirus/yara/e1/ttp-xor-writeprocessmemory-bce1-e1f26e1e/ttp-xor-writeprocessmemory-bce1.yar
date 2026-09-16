rule TTP_XOR_WriteProcessMemory_bce1 {
  strings:
    $key_bce1 = { eb 93 [2] d9 b1 [2] df 84 [2] f1 84 [2] ce 98 }

  condition:
    any of them
}