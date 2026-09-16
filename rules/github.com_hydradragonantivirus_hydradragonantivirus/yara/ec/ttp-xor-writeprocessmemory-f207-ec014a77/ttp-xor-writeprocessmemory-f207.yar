rule TTP_XOR_WriteProcessMemory_f207 {
  strings:
    $key_f207 = { a5 75 [2] 97 57 [2] 91 62 [2] bf 62 [2] 80 7e }

  condition:
    any of them
}