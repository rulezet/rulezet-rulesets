rule TTP_XOR_WriteProcessMemory_2bd5 {
  strings:
    $key_2bd5 = { 7c a7 [2] 4e 85 [2] 48 b0 [2] 66 b0 [2] 59 ac }

  condition:
    any of them
}