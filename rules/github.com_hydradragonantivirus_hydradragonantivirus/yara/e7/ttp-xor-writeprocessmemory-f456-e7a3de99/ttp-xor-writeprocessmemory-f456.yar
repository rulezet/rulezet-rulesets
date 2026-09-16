rule TTP_XOR_WriteProcessMemory_f456 {
  strings:
    $key_f456 = { a3 24 [2] 91 06 [2] 97 33 [2] b9 33 [2] 86 2f }

  condition:
    any of them
}