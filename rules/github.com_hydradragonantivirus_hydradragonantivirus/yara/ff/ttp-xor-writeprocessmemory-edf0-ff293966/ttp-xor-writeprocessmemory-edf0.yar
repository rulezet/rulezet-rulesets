rule TTP_XOR_WriteProcessMemory_edf0 {
  strings:
    $key_edf0 = { ba 82 [2] 88 a0 [2] 8e 95 [2] a0 95 [2] 9f 89 }

  condition:
    any of them
}