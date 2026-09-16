rule TTP_XOR_WriteProcessMemory_54d0 {
  strings:
    $key_54d0 = { 03 a2 [2] 31 80 [2] 37 b5 [2] 19 b5 [2] 26 a9 }

  condition:
    any of them
}