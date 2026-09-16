rule TTP_XOR_WriteProcessMemory_7457 {
  strings:
    $key_7457 = { 23 25 [2] 11 07 [2] 17 32 [2] 39 32 [2] 06 2e }

  condition:
    any of them
}