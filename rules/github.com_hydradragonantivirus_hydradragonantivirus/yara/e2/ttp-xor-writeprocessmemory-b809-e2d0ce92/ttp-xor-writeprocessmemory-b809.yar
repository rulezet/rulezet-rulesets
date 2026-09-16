rule TTP_XOR_WriteProcessMemory_b809 {
  strings:
    $key_b809 = { ef 7b [2] dd 59 [2] db 6c [2] f5 6c [2] ca 70 }

  condition:
    any of them
}