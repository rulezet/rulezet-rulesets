rule TTP_XOR_WriteProcessMemory_d28c {
  strings:
    $key_d28c = { 85 fe [2] b7 dc [2] b1 e9 [2] 9f e9 [2] a0 f5 }

  condition:
    any of them
}