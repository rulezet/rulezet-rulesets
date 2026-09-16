rule TTP_XOR_WriteProcessMemory_90d5 {
  strings:
    $key_90d5 = { c7 a7 [2] f5 85 [2] f3 b0 [2] dd b0 [2] e2 ac }

  condition:
    any of them
}