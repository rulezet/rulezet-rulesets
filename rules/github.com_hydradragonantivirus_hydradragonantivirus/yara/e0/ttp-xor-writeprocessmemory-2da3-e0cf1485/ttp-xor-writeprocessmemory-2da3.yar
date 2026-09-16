rule TTP_XOR_WriteProcessMemory_2da3 {
  strings:
    $key_2da3 = { 7a d1 [2] 48 f3 [2] 4e c6 [2] 60 c6 [2] 5f da }

  condition:
    any of them
}