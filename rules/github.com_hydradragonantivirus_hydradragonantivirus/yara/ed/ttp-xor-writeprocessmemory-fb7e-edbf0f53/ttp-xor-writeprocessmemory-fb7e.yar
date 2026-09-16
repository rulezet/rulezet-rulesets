rule TTP_XOR_WriteProcessMemory_fb7e {
  strings:
    $key_fb7e = { ac 0c [2] 9e 2e [2] 98 1b [2] b6 1b [2] 89 07 }

  condition:
    any of them
}