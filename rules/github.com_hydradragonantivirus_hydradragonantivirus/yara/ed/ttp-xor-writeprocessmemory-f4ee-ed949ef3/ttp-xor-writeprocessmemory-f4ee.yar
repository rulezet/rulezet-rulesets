rule TTP_XOR_WriteProcessMemory_f4ee {
  strings:
    $key_f4ee = { a3 9c [2] 91 be [2] 97 8b [2] b9 8b [2] 86 97 }

  condition:
    any of them
}