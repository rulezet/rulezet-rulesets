rule TTP_XOR_WriteProcessMemory_f4f3 {
  strings:
    $key_f4f3 = { a3 81 [2] 91 a3 [2] 97 96 [2] b9 96 [2] 86 8a }

  condition:
    any of them
}