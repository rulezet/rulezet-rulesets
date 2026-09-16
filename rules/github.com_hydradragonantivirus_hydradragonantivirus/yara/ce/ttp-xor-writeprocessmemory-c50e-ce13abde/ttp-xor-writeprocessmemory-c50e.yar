rule TTP_XOR_WriteProcessMemory_c50e {
  strings:
    $key_c50e = { 92 7c [2] a0 5e [2] a6 6b [2] 88 6b [2] b7 77 }

  condition:
    any of them
}