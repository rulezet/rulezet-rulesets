rule TTP_XOR_WriteProcessMemory_af3d {
  strings:
    $key_af3d = { f8 4f [2] ca 6d [2] cc 58 [2] e2 58 [2] dd 44 }

  condition:
    any of them
}