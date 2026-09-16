rule TTP_XOR_WriteProcessMemory_f4f6 {
  strings:
    $key_f4f6 = { a3 84 [2] 91 a6 [2] 97 93 [2] b9 93 [2] 86 8f }

  condition:
    any of them
}