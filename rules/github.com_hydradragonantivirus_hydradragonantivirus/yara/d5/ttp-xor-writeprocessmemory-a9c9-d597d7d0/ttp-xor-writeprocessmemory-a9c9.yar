rule TTP_XOR_WriteProcessMemory_a9c9 {
  strings:
    $key_a9c9 = { fe bb [2] cc 99 [2] ca ac [2] e4 ac [2] db b0 }

  condition:
    any of them
}