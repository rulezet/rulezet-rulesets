rule TTP_XOR_WriteProcessMemory_af31 {
  strings:
    $key_af31 = { f8 43 [2] ca 61 [2] cc 54 [2] e2 54 [2] dd 48 }

  condition:
    any of them
}