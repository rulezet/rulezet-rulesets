rule TTP_XOR_WriteProcessMemory_ad23 {
  strings:
    $key_ad23 = { fa 51 [2] c8 73 [2] ce 46 [2] e0 46 [2] df 5a }

  condition:
    any of them
}