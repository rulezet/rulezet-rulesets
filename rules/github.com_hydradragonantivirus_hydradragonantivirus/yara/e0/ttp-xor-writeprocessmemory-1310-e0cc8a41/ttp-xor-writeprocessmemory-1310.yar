rule TTP_XOR_WriteProcessMemory_1310 {
  strings:
    $key_1310 = { 44 62 [2] 76 40 [2] 70 75 [2] 5e 75 [2] 61 69 }

  condition:
    any of them
}