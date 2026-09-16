rule TTP_XOR_WriteProcessMemory_a94b {
  strings:
    $key_a94b = { fe 39 [2] cc 1b [2] ca 2e [2] e4 2e [2] db 32 }

  condition:
    any of them
}