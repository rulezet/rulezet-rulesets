rule TTP_XOR_WriteProcessMemory_fb52 {
  strings:
    $key_fb52 = { ac 20 [2] 9e 02 [2] 98 37 [2] b6 37 [2] 89 2b }

  condition:
    any of them
}