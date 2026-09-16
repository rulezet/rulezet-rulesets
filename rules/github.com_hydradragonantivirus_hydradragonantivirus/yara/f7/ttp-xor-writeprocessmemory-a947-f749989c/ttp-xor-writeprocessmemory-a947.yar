rule TTP_XOR_WriteProcessMemory_a947 {
  strings:
    $key_a947 = { fe 35 [2] cc 17 [2] ca 22 [2] e4 22 [2] db 3e }

  condition:
    any of them
}