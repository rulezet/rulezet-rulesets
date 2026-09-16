rule TTP_XOR_WriteProcessMemory_273d {
  strings:
    $key_273d = { 70 4f [2] 42 6d [2] 44 58 [2] 6a 58 [2] 55 44 }

  condition:
    any of them
}