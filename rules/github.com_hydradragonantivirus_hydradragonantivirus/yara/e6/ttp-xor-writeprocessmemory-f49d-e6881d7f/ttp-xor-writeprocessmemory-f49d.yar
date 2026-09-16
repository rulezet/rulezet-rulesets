rule TTP_XOR_WriteProcessMemory_f49d {
  strings:
    $key_f49d = { a3 ef [2] 91 cd [2] 97 f8 [2] b9 f8 [2] 86 e4 }

  condition:
    any of them
}