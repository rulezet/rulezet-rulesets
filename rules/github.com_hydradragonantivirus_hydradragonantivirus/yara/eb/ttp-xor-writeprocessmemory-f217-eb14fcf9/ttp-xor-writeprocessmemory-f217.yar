rule TTP_XOR_WriteProcessMemory_f217 {
  strings:
    $key_f217 = { a5 65 [2] 97 47 [2] 91 72 [2] bf 72 [2] 80 6e }

  condition:
    any of them
}