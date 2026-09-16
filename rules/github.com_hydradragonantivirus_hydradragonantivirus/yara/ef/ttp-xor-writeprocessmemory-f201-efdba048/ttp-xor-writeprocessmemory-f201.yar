rule TTP_XOR_WriteProcessMemory_f201 {
  strings:
    $key_f201 = { a5 73 [2] 97 51 [2] 91 64 [2] bf 64 [2] 80 78 }

  condition:
    any of them
}