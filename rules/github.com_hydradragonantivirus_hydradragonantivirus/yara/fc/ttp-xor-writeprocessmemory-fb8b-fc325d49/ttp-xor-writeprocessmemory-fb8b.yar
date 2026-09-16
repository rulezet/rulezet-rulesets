rule TTP_XOR_WriteProcessMemory_fb8b {
  strings:
    $key_fb8b = { ac f9 [2] 9e db [2] 98 ee [2] b6 ee [2] 89 f2 }

  condition:
    any of them
}