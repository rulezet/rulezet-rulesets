rule TTP_XOR_WriteProcessMemory_fb4b {
  strings:
    $key_fb4b = { ac 39 [2] 9e 1b [2] 98 2e [2] b6 2e [2] 89 32 }

  condition:
    any of them
}