rule TTP_XOR_WriteProcessMemory_f4a9 {
  strings:
    $key_f4a9 = { a3 db [2] 91 f9 [2] 97 cc [2] b9 cc [2] 86 d0 }

  condition:
    any of them
}