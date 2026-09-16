rule TTP_XOR_WriteProcessMemory_ad51 {
  strings:
    $key_ad51 = { fa 23 [2] c8 01 [2] ce 34 [2] e0 34 [2] df 28 }

  condition:
    any of them
}