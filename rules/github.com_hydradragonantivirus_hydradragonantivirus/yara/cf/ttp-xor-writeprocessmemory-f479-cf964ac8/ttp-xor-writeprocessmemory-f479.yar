rule TTP_XOR_WriteProcessMemory_f479 {
  strings:
    $key_f479 = { a3 0b [2] 91 29 [2] 97 1c [2] b9 1c [2] 86 00 }

  condition:
    any of them
}