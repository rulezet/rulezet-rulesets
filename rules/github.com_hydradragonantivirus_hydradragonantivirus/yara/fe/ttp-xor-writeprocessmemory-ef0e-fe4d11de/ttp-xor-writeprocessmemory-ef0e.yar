rule TTP_XOR_WriteProcessMemory_ef0e {
  strings:
    $key_ef0e = { b8 7c [2] 8a 5e [2] 8c 6b [2] a2 6b [2] 9d 77 }

  condition:
    any of them
}