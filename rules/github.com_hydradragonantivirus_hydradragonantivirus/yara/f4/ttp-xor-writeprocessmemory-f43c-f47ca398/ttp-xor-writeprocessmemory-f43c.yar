rule TTP_XOR_WriteProcessMemory_f43c {
  strings:
    $key_f43c = { a3 4e [2] 91 6c [2] 97 59 [2] b9 59 [2] 86 45 }

  condition:
    any of them
}