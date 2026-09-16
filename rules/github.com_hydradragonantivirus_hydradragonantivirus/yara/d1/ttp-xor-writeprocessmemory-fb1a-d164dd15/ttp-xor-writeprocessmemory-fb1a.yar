rule TTP_XOR_WriteProcessMemory_fb1a {
  strings:
    $key_fb1a = { ac 68 [2] 9e 4a [2] 98 7f [2] b6 7f [2] 89 63 }

  condition:
    any of them
}