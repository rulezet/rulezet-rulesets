rule TTP_XOR_WriteProcessMemory_01d5 {
  strings:
    $key_01d5 = { 56 a7 [2] 64 85 [2] 62 b0 [2] 4c b0 [2] 73 ac }

  condition:
    any of them
}