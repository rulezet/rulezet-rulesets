rule TTP_XOR_WriteProcessMemory_f457 {
  strings:
    $key_f457 = { a3 25 [2] 91 07 [2] 97 32 [2] b9 32 [2] 86 2e }

  condition:
    any of them
}