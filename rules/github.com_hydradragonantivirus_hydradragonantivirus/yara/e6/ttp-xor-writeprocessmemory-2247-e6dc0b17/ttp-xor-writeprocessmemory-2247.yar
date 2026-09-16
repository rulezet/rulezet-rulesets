rule TTP_XOR_WriteProcessMemory_2247 {
  strings:
    $key_2247 = { 75 35 [2] 47 17 [2] 41 22 [2] 6f 22 [2] 50 3e }

  condition:
    any of them
}