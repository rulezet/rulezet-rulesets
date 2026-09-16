rule TTP_XOR_WriteProcessMemory_f259 {
  strings:
    $key_f259 = { a5 2b [2] 97 09 [2] 91 3c [2] bf 3c [2] 80 20 }

  condition:
    any of them
}