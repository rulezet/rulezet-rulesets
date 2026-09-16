rule TTP_XOR_WriteProcessMemory_a9cd {
  strings:
    $key_a9cd = { fe bf [2] cc 9d [2] ca a8 [2] e4 a8 [2] db b4 }

  condition:
    any of them
}