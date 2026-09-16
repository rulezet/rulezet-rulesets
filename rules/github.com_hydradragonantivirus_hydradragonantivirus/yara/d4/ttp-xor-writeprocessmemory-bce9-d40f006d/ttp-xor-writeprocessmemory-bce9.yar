rule TTP_XOR_WriteProcessMemory_bce9 {
  strings:
    $key_bce9 = { eb 9b [2] d9 b9 [2] df 8c [2] f1 8c [2] ce 90 }

  condition:
    any of them
}