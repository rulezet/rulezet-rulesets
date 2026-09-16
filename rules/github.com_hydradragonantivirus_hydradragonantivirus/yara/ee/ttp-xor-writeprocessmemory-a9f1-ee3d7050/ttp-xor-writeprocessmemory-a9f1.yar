rule TTP_XOR_WriteProcessMemory_a9f1 {
  strings:
    $key_a9f1 = { fe 83 [2] cc a1 [2] ca 94 [2] e4 94 [2] db 88 }

  condition:
    any of them
}