rule TTP_XOR_WriteProcessMemory_b8f8 {
  strings:
    $key_b8f8 = { ef 8a [2] dd a8 [2] db 9d [2] f5 9d [2] ca 81 }

  condition:
    any of them
}