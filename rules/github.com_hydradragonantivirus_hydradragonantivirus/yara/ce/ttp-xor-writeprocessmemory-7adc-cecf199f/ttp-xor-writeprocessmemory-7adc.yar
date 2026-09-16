rule TTP_XOR_WriteProcessMemory_7adc {
  strings:
    $key_7adc = { 2d ae [2] 1f 8c [2] 19 b9 [2] 37 b9 [2] 08 a5 }

  condition:
    any of them
}