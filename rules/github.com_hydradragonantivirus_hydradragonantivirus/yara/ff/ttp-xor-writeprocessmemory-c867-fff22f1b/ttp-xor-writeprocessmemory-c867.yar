rule TTP_XOR_WriteProcessMemory_c867 {
  strings:
    $key_c867 = { 9f 15 [2] ad 37 [2] ab 02 [2] 85 02 [2] ba 1e }

  condition:
    any of them
}