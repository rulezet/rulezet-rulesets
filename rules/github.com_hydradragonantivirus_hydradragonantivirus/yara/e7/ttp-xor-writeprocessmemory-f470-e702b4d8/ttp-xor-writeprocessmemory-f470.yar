rule TTP_XOR_WriteProcessMemory_f470 {
  strings:
    $key_f470 = { a3 02 [2] 91 20 [2] 97 15 [2] b9 15 [2] 86 09 }

  condition:
    any of them
}