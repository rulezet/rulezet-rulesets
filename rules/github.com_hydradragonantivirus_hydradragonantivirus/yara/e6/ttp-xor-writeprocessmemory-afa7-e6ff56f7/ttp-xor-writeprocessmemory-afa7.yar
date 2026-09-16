rule TTP_XOR_WriteProcessMemory_afa7 {
  strings:
    $key_afa7 = { f8 d5 [2] ca f7 [2] cc c2 [2] e2 c2 [2] dd de }

  condition:
    any of them
}