rule TTP_XOR_WriteProcessMemory_b8e9 {
  strings:
    $key_b8e9 = { ef 9b [2] dd b9 [2] db 8c [2] f5 8c [2] ca 90 }

  condition:
    any of them
}