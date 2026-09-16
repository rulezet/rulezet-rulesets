rule TTP_XOR_WriteProcessMemory_e30e {
  strings:
    $key_e30e = { b4 7c [2] 86 5e [2] 80 6b [2] ae 6b [2] 91 77 }

  condition:
    any of them
}