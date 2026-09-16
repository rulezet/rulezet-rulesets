rule TTP_XOR_WriteProcessMemory_fb3b {
  strings:
    $key_fb3b = { ac 49 [2] 9e 6b [2] 98 5e [2] b6 5e [2] 89 42 }

  condition:
    any of them
}