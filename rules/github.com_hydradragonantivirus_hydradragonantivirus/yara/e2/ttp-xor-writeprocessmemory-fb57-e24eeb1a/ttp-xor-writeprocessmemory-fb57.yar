rule TTP_XOR_WriteProcessMemory_fb57 {
  strings:
    $key_fb57 = { ac 25 [2] 9e 07 [2] 98 32 [2] b6 32 [2] 89 2e }

  condition:
    any of them
}