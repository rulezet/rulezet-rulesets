rule TTP_XOR_WriteProcessMemory_fb4d {
  strings:
    $key_fb4d = { ac 3f [2] 9e 1d [2] 98 28 [2] b6 28 [2] 89 34 }

  condition:
    any of them
}