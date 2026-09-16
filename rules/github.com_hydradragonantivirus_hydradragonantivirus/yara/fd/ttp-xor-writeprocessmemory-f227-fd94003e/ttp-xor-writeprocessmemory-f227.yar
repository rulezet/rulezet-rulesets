rule TTP_XOR_WriteProcessMemory_f227 {
  strings:
    $key_f227 = { a5 55 [2] 97 77 [2] 91 42 [2] bf 42 [2] 80 5e }

  condition:
    any of them
}