rule TTP_XOR_WriteProcessMemory_c877 {
  strings:
    $key_c877 = { 9f 05 [2] ad 27 [2] ab 12 [2] 85 12 [2] ba 0e }

  condition:
    any of them
}