rule TTP_XOR_WriteProcessMemory_affb {
  strings:
    $key_affb = { f8 89 [2] ca ab [2] cc 9e [2] e2 9e [2] dd 82 }

  condition:
    any of them
}