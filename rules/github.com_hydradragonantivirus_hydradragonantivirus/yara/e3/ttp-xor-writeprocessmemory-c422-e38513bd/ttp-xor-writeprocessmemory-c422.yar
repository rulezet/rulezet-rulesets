rule TTP_XOR_WriteProcessMemory_c422 {
  strings:
    $key_c422 = { 93 50 [2] a1 72 [2] a7 47 [2] 89 47 [2] b6 5b }

  condition:
    any of them
}