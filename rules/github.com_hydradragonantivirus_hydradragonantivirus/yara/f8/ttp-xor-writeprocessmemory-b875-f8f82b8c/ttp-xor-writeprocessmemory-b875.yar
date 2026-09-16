rule TTP_XOR_WriteProcessMemory_b875 {
  strings:
    $key_b875 = { ef 07 [2] dd 25 [2] db 10 [2] f5 10 [2] ca 0c }

  condition:
    any of them
}