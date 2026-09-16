rule TTP_XOR_WriteProcessMemory_fb70 {
  strings:
    $key_fb70 = { ac 02 [2] 9e 20 [2] 98 15 [2] b6 15 [2] 89 09 }

  condition:
    any of them
}