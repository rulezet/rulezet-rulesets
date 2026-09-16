rule TTP_XOR_WriteProcessMemory_3157 {
  strings:
    $key_3157 = { 66 25 [2] 54 07 [2] 52 32 [2] 7c 32 [2] 43 2e }

  condition:
    any of them
}