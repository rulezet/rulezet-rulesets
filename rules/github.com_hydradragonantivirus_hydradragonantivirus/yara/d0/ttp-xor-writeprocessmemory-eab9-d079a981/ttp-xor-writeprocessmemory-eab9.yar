rule TTP_XOR_WriteProcessMemory_eab9 {
  strings:
    $key_eab9 = { bd cb [2] 8f e9 [2] 89 dc [2] a7 dc [2] 98 c0 }

  condition:
    any of them
}