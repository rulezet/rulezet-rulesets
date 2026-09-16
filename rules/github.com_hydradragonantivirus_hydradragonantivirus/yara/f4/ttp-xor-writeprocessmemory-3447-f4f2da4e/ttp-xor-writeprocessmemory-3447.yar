rule TTP_XOR_WriteProcessMemory_3447 {
  strings:
    $key_3447 = { 63 35 [2] 51 17 [2] 57 22 [2] 79 22 [2] 46 3e }

  condition:
    any of them
}