rule TTP_XOR_WriteProcessMemory_f440 {
  strings:
    $key_f440 = { a3 32 [2] 91 10 [2] 97 25 [2] b9 25 [2] 86 39 }

  condition:
    any of them
}