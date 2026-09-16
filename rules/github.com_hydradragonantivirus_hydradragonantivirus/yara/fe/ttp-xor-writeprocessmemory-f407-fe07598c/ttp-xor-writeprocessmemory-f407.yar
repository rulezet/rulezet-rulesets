rule TTP_XOR_WriteProcessMemory_f407 {
  strings:
    $key_f407 = { a3 75 [2] 91 57 [2] 97 62 [2] b9 62 [2] 86 7e }

  condition:
    any of them
}