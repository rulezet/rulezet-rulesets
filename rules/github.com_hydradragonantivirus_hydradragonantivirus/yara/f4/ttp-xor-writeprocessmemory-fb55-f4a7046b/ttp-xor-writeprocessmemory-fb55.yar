rule TTP_XOR_WriteProcessMemory_fb55 {
  strings:
    $key_fb55 = { ac 27 [2] 9e 05 [2] 98 30 [2] b6 30 [2] 89 2c }

  condition:
    any of them
}