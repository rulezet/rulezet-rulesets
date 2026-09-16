rule TTP_XOR_WriteProcessMemory_ead5 {
  strings:
    $key_ead5 = { bd a7 [2] 8f 85 [2] 89 b0 [2] a7 b0 [2] 98 ac }

  condition:
    any of them
}