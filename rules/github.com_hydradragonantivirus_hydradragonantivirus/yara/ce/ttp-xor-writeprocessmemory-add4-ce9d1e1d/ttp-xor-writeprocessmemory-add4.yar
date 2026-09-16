rule TTP_XOR_WriteProcessMemory_add4 {
  strings:
    $key_add4 = { fa a6 [2] c8 84 [2] ce b1 [2] e0 b1 [2] df ad }

  condition:
    any of them
}