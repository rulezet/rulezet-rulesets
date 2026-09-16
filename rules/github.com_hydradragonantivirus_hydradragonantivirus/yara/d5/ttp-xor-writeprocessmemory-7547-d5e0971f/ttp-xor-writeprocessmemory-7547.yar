rule TTP_XOR_WriteProcessMemory_7547 {
  strings:
    $key_7547 = { 22 35 [2] 10 17 [2] 16 22 [2] 38 22 [2] 07 3e }

  condition:
    any of them
}