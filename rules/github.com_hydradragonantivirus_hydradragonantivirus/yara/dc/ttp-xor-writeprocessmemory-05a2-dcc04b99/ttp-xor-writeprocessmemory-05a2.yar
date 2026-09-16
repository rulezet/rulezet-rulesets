rule TTP_XOR_WriteProcessMemory_05a2 {
  strings:
    $key_05a2 = { 52 d0 [2] 60 f2 [2] 66 c7 [2] 48 c7 [2] 77 db }

  condition:
    any of them
}