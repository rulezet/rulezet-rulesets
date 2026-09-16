rule TTP_XOR_WriteProcessMemory_cec2 {
  strings:
    $key_cec2 = { 99 b0 [2] ab 92 [2] ad a7 [2] 83 a7 [2] bc bb }

  condition:
    any of them
}