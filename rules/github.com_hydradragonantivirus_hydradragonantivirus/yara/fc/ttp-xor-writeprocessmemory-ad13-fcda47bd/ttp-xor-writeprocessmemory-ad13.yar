rule TTP_XOR_WriteProcessMemory_ad13 {
  strings:
    $key_ad13 = { fa 61 [2] c8 43 [2] ce 76 [2] e0 76 [2] df 6a }

  condition:
    any of them
}