rule TTP_XOR_WriteProcessMemory_f46a {
  strings:
    $key_f46a = { a3 18 [2] 91 3a [2] 97 0f [2] b9 0f [2] 86 13 }

  condition:
    any of them
}