rule TTP_XOR_WriteProcessMemory_36a2 {
  strings:
    $key_36a2 = { 61 d0 [2] 53 f2 [2] 55 c7 [2] 7b c7 [2] 44 db }

  condition:
    any of them
}