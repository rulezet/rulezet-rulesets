rule TTP_XOR_WriteProcessMemory_ad42 {
  strings:
    $key_ad42 = { fa 30 [2] c8 12 [2] ce 27 [2] e0 27 [2] df 3b }

  condition:
    any of them
}