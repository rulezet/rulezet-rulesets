rule TTP_XOR_WriteProcessMemory_fb35 {
  strings:
    $key_fb35 = { ac 47 [2] 9e 65 [2] 98 50 [2] b6 50 [2] 89 4c }

  condition:
    any of them
}