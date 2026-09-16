rule TTP_XOR_WriteProcessMemory_f40e {
  strings:
    $key_f40e = { a3 7c [2] 91 5e [2] 97 6b [2] b9 6b [2] 86 77 }

  condition:
    any of them
}