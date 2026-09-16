rule TTP_XOR_WriteProcessMemory_cc80 {
  strings:
    $key_cc80 = { 9b f2 [2] a9 d0 [2] af e5 [2] 81 e5 [2] be f9 }

  condition:
    any of them
}