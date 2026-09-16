rule TTP_XOR_WriteProcessMemory_1098 {
  strings:
    $key_1098 = { 47 ea [2] 75 c8 [2] 73 fd [2] 5d fd [2] 62 e1 }

  condition:
    any of them
}