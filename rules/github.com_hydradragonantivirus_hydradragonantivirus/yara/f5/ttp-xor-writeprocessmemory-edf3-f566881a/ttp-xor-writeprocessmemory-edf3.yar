rule TTP_XOR_WriteProcessMemory_edf3 {
  strings:
    $key_edf3 = { ba 81 [2] 88 a3 [2] 8e 96 [2] a0 96 [2] 9f 8a }

  condition:
    any of them
}