rule TTP_XOR_WriteProcessMemory_adc5 {
  strings:
    $key_adc5 = { fa b7 [2] c8 95 [2] ce a0 [2] e0 a0 [2] df bc }

  condition:
    any of them
}