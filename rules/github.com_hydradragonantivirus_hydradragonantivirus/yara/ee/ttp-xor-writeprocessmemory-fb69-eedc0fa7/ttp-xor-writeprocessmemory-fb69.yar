rule TTP_XOR_WriteProcessMemory_fb69 {
  strings:
    $key_fb69 = { ac 1b [2] 9e 39 [2] 98 0c [2] b6 0c [2] 89 10 }

  condition:
    any of them
}