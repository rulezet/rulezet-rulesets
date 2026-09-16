rule TTP_XOR_WriteProcessMemory_220e {
  strings:
    $key_220e = { 75 7c [2] 47 5e [2] 41 6b [2] 6f 6b [2] 50 77 }

  condition:
    any of them
}