rule TTP_XOR_WriteProcessMemory_fb76 {
  strings:
    $key_fb76 = { ac 04 [2] 9e 26 [2] 98 13 [2] b6 13 [2] 89 0f }

  condition:
    any of them
}