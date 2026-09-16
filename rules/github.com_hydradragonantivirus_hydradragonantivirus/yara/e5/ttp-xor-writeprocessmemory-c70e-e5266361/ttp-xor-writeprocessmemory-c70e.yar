rule TTP_XOR_WriteProcessMemory_c70e {
  strings:
    $key_c70e = { 90 7c [2] a2 5e [2] a4 6b [2] 8a 6b [2] b5 77 }

  condition:
    any of them
}