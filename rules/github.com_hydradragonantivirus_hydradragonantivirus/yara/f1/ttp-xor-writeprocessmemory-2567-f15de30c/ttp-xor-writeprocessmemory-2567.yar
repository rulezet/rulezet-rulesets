rule TTP_XOR_WriteProcessMemory_2567 {
  strings:
    $key_2567 = { 72 15 [2] 40 37 [2] 46 02 [2] 68 02 [2] 57 1e }

  condition:
    any of them
}