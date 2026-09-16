rule TTP_XOR_WriteProcessMemory_ad41 {
  strings:
    $key_ad41 = { fa 33 [2] c8 11 [2] ce 24 [2] e0 24 [2] df 38 }

  condition:
    any of them
}