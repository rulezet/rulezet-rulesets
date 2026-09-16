rule TTP_XOR_WriteProcessMemory_d121 {
  strings:
    $key_d121 = { 86 53 [2] b4 71 [2] b2 44 [2] 9c 44 [2] a3 58 }

  condition:
    any of them
}