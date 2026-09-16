rule TTP_XOR_WriteProcessMemory_fb96 {
  strings:
    $key_fb96 = { ac e4 [2] 9e c6 [2] 98 f3 [2] b6 f3 [2] 89 ef }

  condition:
    any of them
}