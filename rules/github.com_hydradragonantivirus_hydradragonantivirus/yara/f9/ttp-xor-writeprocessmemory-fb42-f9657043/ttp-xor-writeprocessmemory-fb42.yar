rule TTP_XOR_WriteProcessMemory_fb42 {
  strings:
    $key_fb42 = { ac 30 [2] 9e 12 [2] 98 27 [2] b6 27 [2] 89 3b }

  condition:
    any of them
}