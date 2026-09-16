rule TTP_XOR_WriteProcessMemory_8715 {
  strings:
    $key_8715 = { d0 67 [2] e2 45 [2] e4 70 [2] ca 70 [2] f5 6c }

  condition:
    any of them
}