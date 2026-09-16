rule TTP_XOR_WriteProcessMemory_ad07 {
  strings:
    $key_ad07 = { fa 75 [2] c8 57 [2] ce 62 [2] e0 62 [2] df 7e }

  condition:
    any of them
}