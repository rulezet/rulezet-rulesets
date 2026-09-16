rule TTP_XOR_WriteProcessMemory_32a2 {
  strings:
    $key_32a2 = { 65 d0 [2] 57 f2 [2] 51 c7 [2] 7f c7 [2] 40 db }

  condition:
    any of them
}