rule TTP_XOR_WriteProcessMemory_ad63 {
  strings:
    $key_ad63 = { fa 11 [2] c8 33 [2] ce 06 [2] e0 06 [2] df 1a }

  condition:
    any of them
}