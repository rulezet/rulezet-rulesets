rule TTP_XOR_WriteProcessMemory_c813 {
  strings:
    $key_c813 = { 9f 61 [2] ad 43 [2] ab 76 [2] 85 76 [2] ba 6a }

  condition:
    any of them
}