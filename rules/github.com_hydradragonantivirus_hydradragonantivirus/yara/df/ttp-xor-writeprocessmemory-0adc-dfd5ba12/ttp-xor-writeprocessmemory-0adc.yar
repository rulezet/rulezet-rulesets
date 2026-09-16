rule TTP_XOR_WriteProcessMemory_0adc {
  strings:
    $key_0adc = { 5d ae [2] 6f 8c [2] 69 b9 [2] 47 b9 [2] 78 a5 }

  condition:
    any of them
}