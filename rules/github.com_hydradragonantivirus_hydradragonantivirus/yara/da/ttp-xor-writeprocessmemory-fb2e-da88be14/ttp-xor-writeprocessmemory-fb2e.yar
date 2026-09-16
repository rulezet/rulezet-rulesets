rule TTP_XOR_WriteProcessMemory_fb2e {
  strings:
    $key_fb2e = { ac 5c [2] 9e 7e [2] 98 4b [2] b6 4b [2] 89 57 }

  condition:
    any of them
}