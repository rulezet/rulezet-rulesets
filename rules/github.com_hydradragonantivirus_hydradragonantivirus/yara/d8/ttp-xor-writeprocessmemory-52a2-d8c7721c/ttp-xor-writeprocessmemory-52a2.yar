rule TTP_XOR_WriteProcessMemory_52a2 {
  strings:
    $key_52a2 = { 05 d0 [2] 37 f2 [2] 31 c7 [2] 1f c7 [2] 20 db }

  condition:
    any of them
}