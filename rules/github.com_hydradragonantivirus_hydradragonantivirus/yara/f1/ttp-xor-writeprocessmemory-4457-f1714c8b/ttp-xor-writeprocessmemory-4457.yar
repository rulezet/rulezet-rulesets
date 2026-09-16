rule TTP_XOR_WriteProcessMemory_4457 {
  strings:
    $key_4457 = { 13 25 [2] 21 07 [2] 27 32 [2] 09 32 [2] 36 2e }

  condition:
    any of them
}