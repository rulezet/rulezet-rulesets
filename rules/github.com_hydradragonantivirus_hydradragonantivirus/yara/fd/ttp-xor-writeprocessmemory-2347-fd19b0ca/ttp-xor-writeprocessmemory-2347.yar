rule TTP_XOR_WriteProcessMemory_2347 {
  strings:
    $key_2347 = { 74 35 [2] 46 17 [2] 40 22 [2] 6e 22 [2] 51 3e }

  condition:
    any of them
}