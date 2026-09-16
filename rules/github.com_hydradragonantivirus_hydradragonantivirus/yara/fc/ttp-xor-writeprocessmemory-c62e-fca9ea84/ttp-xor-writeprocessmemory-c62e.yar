rule TTP_XOR_WriteProcessMemory_c62e {
  strings:
    $key_c62e = { 91 5c [2] a3 7e [2] a5 4b [2] 8b 4b [2] b4 57 }

  condition:
    any of them
}