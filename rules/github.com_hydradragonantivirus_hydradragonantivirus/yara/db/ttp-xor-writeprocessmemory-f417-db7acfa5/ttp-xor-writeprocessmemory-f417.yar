rule TTP_XOR_WriteProcessMemory_f417 {
  strings:
    $key_f417 = { a3 65 [2] 91 47 [2] 97 72 [2] b9 72 [2] 86 6e }

  condition:
    any of them
}