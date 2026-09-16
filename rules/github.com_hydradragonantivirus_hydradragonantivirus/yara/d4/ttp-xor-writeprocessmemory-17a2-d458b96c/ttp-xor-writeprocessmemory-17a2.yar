rule TTP_XOR_WriteProcessMemory_17a2 {
  strings:
    $key_17a2 = { 40 d0 [2] 72 f2 [2] 74 c7 [2] 5a c7 [2] 65 db }

  condition:
    any of them
}