rule TTP_XOR_WriteProcessMemory_c850 {
  strings:
    $key_c850 = { 9f 22 [2] ad 00 [2] ab 35 [2] 85 35 [2] ba 29 }

  condition:
    any of them
}