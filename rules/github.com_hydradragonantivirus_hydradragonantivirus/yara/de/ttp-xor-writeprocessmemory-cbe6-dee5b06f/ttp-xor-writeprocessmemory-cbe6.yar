rule TTP_XOR_WriteProcessMemory_cbe6 {
  strings:
    $key_cbe6 = { 9c 94 [2] ae b6 [2] a8 83 [2] 86 83 [2] b9 9f }

  condition:
    any of them
}