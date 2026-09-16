rule TTP_XOR_WriteProcessMemory_21d5 {
  strings:
    $key_21d5 = { 76 a7 [2] 44 85 [2] 42 b0 [2] 6c b0 [2] 53 ac }

  condition:
    any of them
}