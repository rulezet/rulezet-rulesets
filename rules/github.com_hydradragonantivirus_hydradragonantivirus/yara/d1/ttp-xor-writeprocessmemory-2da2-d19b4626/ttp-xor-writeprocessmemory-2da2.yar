rule TTP_XOR_WriteProcessMemory_2da2 {
  strings:
    $key_2da2 = { 7a d0 [2] 48 f2 [2] 4e c7 [2] 60 c7 [2] 5f db }

  condition:
    any of them
}