rule TTP_XOR_WriteProcessMemory_c845 {
  strings:
    $key_c845 = { 9f 37 [2] ad 15 [2] ab 20 [2] 85 20 [2] ba 3c }

  condition:
    any of them
}