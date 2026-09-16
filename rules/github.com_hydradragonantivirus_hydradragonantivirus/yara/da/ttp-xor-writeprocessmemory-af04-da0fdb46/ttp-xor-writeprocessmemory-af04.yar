rule TTP_XOR_WriteProcessMemory_af04 {
  strings:
    $key_af04 = { f8 76 [2] ca 54 [2] cc 61 [2] e2 61 [2] dd 7d }

  condition:
    any of them
}