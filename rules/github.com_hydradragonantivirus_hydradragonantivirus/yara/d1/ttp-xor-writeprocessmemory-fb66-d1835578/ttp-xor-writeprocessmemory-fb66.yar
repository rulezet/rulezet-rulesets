rule TTP_XOR_WriteProcessMemory_fb66 {
  strings:
    $key_fb66 = { ac 14 [2] 9e 36 [2] 98 03 [2] b6 03 [2] 89 1f }

  condition:
    any of them
}