rule TTP_XOR_WriteProcessMemory_fb17 {
  strings:
    $key_fb17 = { ac 65 [2] 9e 47 [2] 98 72 [2] b6 72 [2] 89 6e }

  condition:
    any of them
}