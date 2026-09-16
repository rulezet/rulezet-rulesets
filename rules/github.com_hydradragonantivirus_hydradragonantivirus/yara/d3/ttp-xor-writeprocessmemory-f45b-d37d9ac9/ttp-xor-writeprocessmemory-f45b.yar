rule TTP_XOR_WriteProcessMemory_f45b {
  strings:
    $key_f45b = { a3 29 [2] 91 0b [2] 97 3e [2] b9 3e [2] 86 22 }

  condition:
    any of them
}