rule TTP_XOR_WriteProcessMemory_00b4 {
  strings:
    $key_00b4 = { 57 c6 [2] 65 e4 [2] 63 d1 [2] 4d d1 [2] 72 cd }

  condition:
    any of them
}