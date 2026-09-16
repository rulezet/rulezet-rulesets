rule TTP_XOR_WriteProcessMemory_24b0 {
  strings:
    $key_24b0 = { 73 c2 [2] 41 e0 [2] 47 d5 [2] 69 d5 [2] 56 c9 }

  condition:
    any of them
}