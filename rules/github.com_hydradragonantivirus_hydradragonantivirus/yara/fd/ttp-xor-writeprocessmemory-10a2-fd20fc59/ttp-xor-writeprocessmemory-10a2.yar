rule TTP_XOR_WriteProcessMemory_10a2 {
  strings:
    $key_10a2 = { 47 d0 [2] 75 f2 [2] 73 c7 [2] 5d c7 [2] 62 db }

  condition:
    any of them
}