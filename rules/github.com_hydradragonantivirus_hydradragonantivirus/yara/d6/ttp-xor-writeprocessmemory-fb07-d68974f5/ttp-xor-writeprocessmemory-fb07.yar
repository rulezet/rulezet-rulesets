rule TTP_XOR_WriteProcessMemory_fb07 {
  strings:
    $key_fb07 = { ac 75 [2] 9e 57 [2] 98 62 [2] b6 62 [2] 89 7e }

  condition:
    any of them
}