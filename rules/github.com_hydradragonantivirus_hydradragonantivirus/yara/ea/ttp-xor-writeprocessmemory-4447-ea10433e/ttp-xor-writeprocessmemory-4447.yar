rule TTP_XOR_WriteProcessMemory_4447 {
  strings:
    $key_4447 = { 13 35 [2] 21 17 [2] 27 22 [2] 09 22 [2] 36 3e }

  condition:
    any of them
}