rule TTP_XOR_WriteProcessMemory_ef5b {
  strings:
    $key_ef5b = { b8 29 [2] 8a 0b [2] 8c 3e [2] a2 3e [2] 9d 22 }

  condition:
    any of them
}