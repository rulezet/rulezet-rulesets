rule TTP_XOR_WriteProcessMemory_bce2 {
  strings:
    $key_bce2 = { eb 90 [2] d9 b2 [2] df 87 [2] f1 87 [2] ce 9b }

  condition:
    any of them
}