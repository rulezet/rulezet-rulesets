rule TTP_XOR_WriteProcessMemory_af15 {
  strings:
    $key_af15 = { f8 67 [2] ca 45 [2] cc 70 [2] e2 70 [2] dd 6c }

  condition:
    any of them
}