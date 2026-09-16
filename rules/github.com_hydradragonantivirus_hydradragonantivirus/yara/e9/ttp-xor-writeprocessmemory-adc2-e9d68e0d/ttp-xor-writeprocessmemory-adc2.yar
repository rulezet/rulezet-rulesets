rule TTP_XOR_WriteProcessMemory_adc2 {
  strings:
    $key_adc2 = { fa b0 [2] c8 92 [2] ce a7 [2] e0 a7 [2] df bb }

  condition:
    any of them
}