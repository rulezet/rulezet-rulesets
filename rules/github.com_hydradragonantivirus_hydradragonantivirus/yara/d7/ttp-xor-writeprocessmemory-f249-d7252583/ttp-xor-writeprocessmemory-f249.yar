rule TTP_XOR_WriteProcessMemory_f249 {
  strings:
    $key_f249 = { a5 3b [2] 97 19 [2] 91 2c [2] bf 2c [2] 80 30 }

  condition:
    any of them
}