rule TTP_XOR_WriteProcessMemory_3247 {
  strings:
    $key_3247 = { 65 35 [2] 57 17 [2] 51 22 [2] 7f 22 [2] 40 3e }

  condition:
    any of them
}