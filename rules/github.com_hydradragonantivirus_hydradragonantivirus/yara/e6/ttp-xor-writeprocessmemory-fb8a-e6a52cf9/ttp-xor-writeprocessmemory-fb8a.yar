rule TTP_XOR_WriteProcessMemory_fb8a {
  strings:
    $key_fb8a = { ac f8 [2] 9e da [2] 98 ef [2] b6 ef [2] 89 f3 }

  condition:
    any of them
}