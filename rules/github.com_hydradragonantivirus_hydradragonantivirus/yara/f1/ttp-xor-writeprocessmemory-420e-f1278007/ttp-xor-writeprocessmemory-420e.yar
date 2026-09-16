rule TTP_XOR_WriteProcessMemory_420e {
  strings:
    $key_420e = { 15 7c [2] 27 5e [2] 21 6b [2] 0f 6b [2] 30 77 }

  condition:
    any of them
}