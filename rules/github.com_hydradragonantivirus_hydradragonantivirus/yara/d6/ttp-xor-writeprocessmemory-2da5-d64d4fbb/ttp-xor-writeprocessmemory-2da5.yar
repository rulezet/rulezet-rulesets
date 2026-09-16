rule TTP_XOR_WriteProcessMemory_2da5 {
  strings:
    $key_2da5 = { 7a d7 [2] 48 f5 [2] 4e c0 [2] 60 c0 [2] 5f dc }

  condition:
    any of them
}