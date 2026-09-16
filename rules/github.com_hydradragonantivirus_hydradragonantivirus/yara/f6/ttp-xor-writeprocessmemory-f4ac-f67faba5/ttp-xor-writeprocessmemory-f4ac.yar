rule TTP_XOR_WriteProcessMemory_f4ac {
  strings:
    $key_f4ac = { a3 de [2] 91 fc [2] 97 c9 [2] b9 c9 [2] 86 d5 }

  condition:
    any of them
}