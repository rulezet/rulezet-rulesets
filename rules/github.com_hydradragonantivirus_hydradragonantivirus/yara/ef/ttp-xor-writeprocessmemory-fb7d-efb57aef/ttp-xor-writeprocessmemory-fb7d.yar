rule TTP_XOR_WriteProcessMemory_fb7d {
  strings:
    $key_fb7d = { ac 0f [2] 9e 2d [2] 98 18 [2] b6 18 [2] 89 04 }

  condition:
    any of them
}