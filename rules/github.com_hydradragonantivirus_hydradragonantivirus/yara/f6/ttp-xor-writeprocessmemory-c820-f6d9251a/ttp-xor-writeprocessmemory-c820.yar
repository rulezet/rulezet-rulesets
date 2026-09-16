rule TTP_XOR_WriteProcessMemory_c820 {
  strings:
    $key_c820 = { 9f 52 [2] ad 70 [2] ab 45 [2] 85 45 [2] ba 59 }

  condition:
    any of them
}