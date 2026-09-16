rule TTP_XOR_WriteProcessMemory_afc1 {
  strings:
    $key_afc1 = { f8 b3 [2] ca 91 [2] cc a4 [2] e2 a4 [2] dd b8 }

  condition:
    any of them
}