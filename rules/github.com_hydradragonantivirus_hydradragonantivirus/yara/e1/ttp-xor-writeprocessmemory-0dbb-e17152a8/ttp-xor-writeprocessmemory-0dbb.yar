rule TTP_XOR_WriteProcessMemory_0dbb {
  strings:
    $key_0dbb = { 5a c9 [2] 68 eb [2] 6e de [2] 40 de [2] 7f c2 }

  condition:
    any of them
}