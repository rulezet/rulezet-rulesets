rule TTP_XOR_WriteProcessMemory_fb45 {
  strings:
    $key_fb45 = { ac 37 [2] 9e 15 [2] 98 20 [2] b6 20 [2] 89 3c }

  condition:
    any of them
}