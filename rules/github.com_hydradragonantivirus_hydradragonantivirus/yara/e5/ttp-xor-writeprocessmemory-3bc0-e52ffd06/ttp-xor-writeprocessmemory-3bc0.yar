rule TTP_XOR_WriteProcessMemory_3bc0 {
  strings:
    $key_3bc0 = { 6c b2 [2] 5e 90 [2] 58 a5 [2] 76 a5 [2] 49 b9 }

  condition:
    any of them
}