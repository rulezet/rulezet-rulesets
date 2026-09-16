rule TTP_XOR_WriteProcessMemory_a929 {
  strings:
    $key_a929 = { fe 5b [2] cc 79 [2] ca 4c [2] e4 4c [2] db 50 }

  condition:
    any of them
}