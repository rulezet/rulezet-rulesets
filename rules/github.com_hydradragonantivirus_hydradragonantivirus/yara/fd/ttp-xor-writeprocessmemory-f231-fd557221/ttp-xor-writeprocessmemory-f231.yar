rule TTP_XOR_WriteProcessMemory_f231 {
  strings:
    $key_f231 = { a5 43 [2] 97 61 [2] 91 54 [2] bf 54 [2] 80 48 }

  condition:
    any of them
}