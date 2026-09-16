rule TTP_XOR_WriteProcessMemory_2537 {
  strings:
    $key_2537 = { 72 45 [2] 40 67 [2] 46 52 [2] 68 52 [2] 57 4e }

  condition:
    any of them
}