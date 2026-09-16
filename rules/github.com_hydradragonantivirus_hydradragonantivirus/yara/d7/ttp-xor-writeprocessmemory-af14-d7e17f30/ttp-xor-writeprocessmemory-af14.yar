rule TTP_XOR_WriteProcessMemory_af14 {
  strings:
    $key_af14 = { f8 66 [2] ca 44 [2] cc 71 [2] e2 71 [2] dd 6d }

  condition:
    any of them
}