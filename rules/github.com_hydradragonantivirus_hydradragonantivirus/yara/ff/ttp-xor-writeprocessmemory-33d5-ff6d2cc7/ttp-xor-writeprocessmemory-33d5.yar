rule TTP_XOR_WriteProcessMemory_33d5 {
  strings:
    $key_33d5 = { 64 a7 [2] 56 85 [2] 50 b0 [2] 7e b0 [2] 41 ac }

  condition:
    any of them
}