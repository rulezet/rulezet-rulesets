rule TTP_XOR_WriteProcessMemory_34a2 {
  strings:
    $key_34a2 = { 63 d0 [2] 51 f2 [2] 57 c7 [2] 79 c7 [2] 46 db }

  condition:
    any of them
}