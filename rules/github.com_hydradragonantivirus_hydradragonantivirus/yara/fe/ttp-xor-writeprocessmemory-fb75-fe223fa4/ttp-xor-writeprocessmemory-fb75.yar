rule TTP_XOR_WriteProcessMemory_fb75 {
  strings:
    $key_fb75 = { ac 07 [2] 9e 25 [2] 98 10 [2] b6 10 [2] 89 0c }

  condition:
    any of them
}