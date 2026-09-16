rule TTP_XOR_WriteProcessMemory_2324 {
  strings:
    $key_2324 = { 74 56 [2] 46 74 [2] 40 41 [2] 6e 41 [2] 51 5d }

  condition:
    any of them
}