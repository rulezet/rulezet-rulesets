rule TTP_XOR_WriteProcessMemory_adc3 {
  strings:
    $key_adc3 = { fa b1 [2] c8 93 [2] ce a6 [2] e0 a6 [2] df ba }

  condition:
    any of them
}