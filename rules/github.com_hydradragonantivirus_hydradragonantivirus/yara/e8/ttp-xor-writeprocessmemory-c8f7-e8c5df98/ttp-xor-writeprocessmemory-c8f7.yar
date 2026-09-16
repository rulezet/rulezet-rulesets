rule TTP_XOR_WriteProcessMemory_c8f7 {
  strings:
    $key_c8f7 = { 9f 85 [2] ad a7 [2] ab 92 [2] 85 92 [2] ba 8e }

  condition:
    any of them
}