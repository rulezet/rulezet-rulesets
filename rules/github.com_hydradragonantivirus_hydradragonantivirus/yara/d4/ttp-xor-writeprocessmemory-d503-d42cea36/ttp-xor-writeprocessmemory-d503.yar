rule TTP_XOR_WriteProcessMemory_d503 {
  strings:
    $key_d503 = { 82 71 [2] b0 53 [2] b6 66 [2] 98 66 [2] a7 7a }

  condition:
    any of them
}