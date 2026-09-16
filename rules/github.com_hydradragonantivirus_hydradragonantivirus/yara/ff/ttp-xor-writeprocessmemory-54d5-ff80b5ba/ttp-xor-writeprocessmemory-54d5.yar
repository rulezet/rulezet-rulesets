rule TTP_XOR_WriteProcessMemory_54d5 {
  strings:
    $key_54d5 = { 03 a7 [2] 31 85 [2] 37 b0 [2] 19 b0 [2] 26 ac }

  condition:
    any of them
}