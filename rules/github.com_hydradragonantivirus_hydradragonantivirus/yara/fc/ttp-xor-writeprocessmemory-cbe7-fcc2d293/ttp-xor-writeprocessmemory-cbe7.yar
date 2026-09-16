rule TTP_XOR_WriteProcessMemory_cbe7 {
  strings:
    $key_cbe7 = { 9c 95 [2] ae b7 [2] a8 82 [2] 86 82 [2] b9 9e }

  condition:
    any of them
}