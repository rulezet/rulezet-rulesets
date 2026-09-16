rule TTP_XOR_WriteProcessMemory_adc6 {
  strings:
    $key_adc6 = { fa b4 [2] c8 96 [2] ce a3 [2] e0 a3 [2] df bf }

  condition:
    any of them
}