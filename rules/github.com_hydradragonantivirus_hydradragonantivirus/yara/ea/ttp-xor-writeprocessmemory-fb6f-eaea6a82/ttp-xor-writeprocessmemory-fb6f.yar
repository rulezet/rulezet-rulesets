rule TTP_XOR_WriteProcessMemory_fb6f {
  strings:
    $key_fb6f = { ac 1d [2] 9e 3f [2] 98 0a [2] b6 0a [2] 89 16 }

  condition:
    any of them
}