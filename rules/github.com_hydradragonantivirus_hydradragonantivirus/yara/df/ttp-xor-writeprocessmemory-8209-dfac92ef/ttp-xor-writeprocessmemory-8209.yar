rule TTP_XOR_WriteProcessMemory_8209 {
  strings:
    $key_8209 = { d5 7b [2] e7 59 [2] e1 6c [2] cf 6c [2] f0 70 }

  condition:
    any of them
}