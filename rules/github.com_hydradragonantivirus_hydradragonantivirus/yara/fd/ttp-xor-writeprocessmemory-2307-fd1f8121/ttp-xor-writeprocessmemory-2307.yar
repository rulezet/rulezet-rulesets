rule TTP_XOR_WriteProcessMemory_2307 {
  strings:
    $key_2307 = { 74 75 [2] 46 57 [2] 40 62 [2] 6e 62 [2] 51 7e }

  condition:
    any of them
}