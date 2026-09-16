rule TTP_XOR_WriteProcessMemory_f4ea {
  strings:
    $key_f4ea = { a3 98 [2] 91 ba [2] 97 8f [2] b9 8f [2] 86 93 }

  condition:
    any of them
}