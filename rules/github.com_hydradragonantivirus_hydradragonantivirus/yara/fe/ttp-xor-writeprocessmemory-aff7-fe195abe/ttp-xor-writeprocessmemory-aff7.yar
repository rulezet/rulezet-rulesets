rule TTP_XOR_WriteProcessMemory_aff7 {
  strings:
    $key_aff7 = { f8 85 [2] ca a7 [2] cc 92 [2] e2 92 [2] dd 8e }

  condition:
    any of them
}