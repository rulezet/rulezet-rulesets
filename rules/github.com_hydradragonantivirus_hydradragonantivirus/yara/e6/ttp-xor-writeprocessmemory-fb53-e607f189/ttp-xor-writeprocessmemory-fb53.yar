rule TTP_XOR_WriteProcessMemory_fb53 {
  strings:
    $key_fb53 = { ac 21 [2] 9e 03 [2] 98 36 [2] b6 36 [2] 89 2a }

  condition:
    any of them
}