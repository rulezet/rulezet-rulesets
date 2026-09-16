rule TTP_XOR_WriteProcessMemory_f4ed {
  strings:
    $key_f4ed = { a3 9f [2] 91 bd [2] 97 88 [2] b9 88 [2] 86 94 }

  condition:
    any of them
}