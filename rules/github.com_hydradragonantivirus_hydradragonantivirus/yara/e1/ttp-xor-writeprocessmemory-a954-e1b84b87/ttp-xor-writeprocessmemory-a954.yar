rule TTP_XOR_WriteProcessMemory_a954 {
  strings:
    $key_a954 = { fe 26 [2] cc 04 [2] ca 31 [2] e4 31 [2] db 2d }

  condition:
    any of them
}