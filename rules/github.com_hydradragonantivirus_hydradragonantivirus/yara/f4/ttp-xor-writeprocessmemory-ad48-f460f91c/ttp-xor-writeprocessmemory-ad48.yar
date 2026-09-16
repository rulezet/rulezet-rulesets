rule TTP_XOR_WriteProcessMemory_ad48 {
  strings:
    $key_ad48 = { fa 3a [2] c8 18 [2] ce 2d [2] e0 2d [2] df 31 }

  condition:
    any of them
}