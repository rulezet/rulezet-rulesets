rule TTP_XOR_WriteProcessMemory_fb43 {
  strings:
    $key_fb43 = { ac 31 [2] 9e 13 [2] 98 26 [2] b6 26 [2] 89 3a }

  condition:
    any of them
}