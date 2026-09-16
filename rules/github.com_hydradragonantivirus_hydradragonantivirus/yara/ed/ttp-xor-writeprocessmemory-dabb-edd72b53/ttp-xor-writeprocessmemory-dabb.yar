rule TTP_XOR_WriteProcessMemory_dabb {
  strings:
    $key_dabb = { 8d c9 [2] bf eb [2] b9 de [2] 97 de [2] a8 c2 }

  condition:
    any of them
}