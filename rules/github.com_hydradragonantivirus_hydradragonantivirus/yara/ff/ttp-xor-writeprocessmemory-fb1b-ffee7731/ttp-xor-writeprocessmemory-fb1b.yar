rule TTP_XOR_WriteProcessMemory_fb1b {
  strings:
    $key_fb1b = { ac 69 [2] 9e 4b [2] 98 7e [2] b6 7e [2] 89 62 }

  condition:
    any of them
}