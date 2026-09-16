rule TTP_XOR_WriteProcessMemory_af05 {
  strings:
    $key_af05 = { f8 77 [2] ca 55 [2] cc 60 [2] e2 60 [2] dd 7c }

  condition:
    any of them
}