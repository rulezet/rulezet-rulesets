rule TTP_XOR_WriteProcessMemory_f410 {
  strings:
    $key_f410 = { a3 62 [2] 91 40 [2] 97 75 [2] b9 75 [2] 86 69 }

  condition:
    any of them
}