rule TTP_XOR_WriteProcessMemory_c40e {
  strings:
    $key_c40e = { 93 7c [2] a1 5e [2] a7 6b [2] 89 6b [2] b6 77 }

  condition:
    any of them
}