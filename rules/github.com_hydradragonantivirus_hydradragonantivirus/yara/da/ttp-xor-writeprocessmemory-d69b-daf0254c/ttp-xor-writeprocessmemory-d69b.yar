rule TTP_XOR_WriteProcessMemory_d69b {
  strings:
    $key_d69b = { 81 e9 [2] b3 cb [2] b5 fe [2] 9b fe [2] a4 e2 }

  condition:
    any of them
}