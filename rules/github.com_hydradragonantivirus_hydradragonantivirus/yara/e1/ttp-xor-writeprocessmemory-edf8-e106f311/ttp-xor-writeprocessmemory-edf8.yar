rule TTP_XOR_WriteProcessMemory_edf8 {
  strings:
    $key_edf8 = { ba 8a [2] 88 a8 [2] 8e 9d [2] a0 9d [2] 9f 81 }

  condition:
    any of them
}