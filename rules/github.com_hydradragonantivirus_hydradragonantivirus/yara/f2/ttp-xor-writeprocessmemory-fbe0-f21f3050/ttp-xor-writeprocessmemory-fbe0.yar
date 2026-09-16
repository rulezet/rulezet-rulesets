rule TTP_XOR_WriteProcessMemory_fbe0 {
  strings:
    $key_fbe0 = { ac 92 [2] 9e b0 [2] 98 85 [2] b6 85 [2] 89 99 }

  condition:
    any of them
}