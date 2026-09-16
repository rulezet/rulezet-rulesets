rule TTP_XOR_WriteProcessMemory_d78c {
  strings:
    $key_d78c = { 80 fe [2] b2 dc [2] b4 e9 [2] 9a e9 [2] a5 f5 }

  condition:
    any of them
}