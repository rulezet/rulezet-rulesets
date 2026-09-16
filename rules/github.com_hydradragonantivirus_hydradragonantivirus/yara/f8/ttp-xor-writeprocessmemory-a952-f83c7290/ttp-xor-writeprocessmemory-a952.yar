rule TTP_XOR_WriteProcessMemory_a952 {
  strings:
    $key_a952 = { fe 20 [2] cc 02 [2] ca 37 [2] e4 37 [2] db 2b }

  condition:
    any of them
}