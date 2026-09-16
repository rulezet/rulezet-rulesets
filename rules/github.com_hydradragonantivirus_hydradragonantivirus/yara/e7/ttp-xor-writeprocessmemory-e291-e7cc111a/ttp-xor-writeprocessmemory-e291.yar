rule TTP_XOR_WriteProcessMemory_e291 {
  strings:
    $key_e291 = { b5 e3 [2] 87 c1 [2] 81 f4 [2] af f4 [2] 90 e8 }

  condition:
    any of them
}