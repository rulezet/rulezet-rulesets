rule TTP_XOR_WriteProcessMemory_140e {
  strings:
    $key_140e = { 43 7c [2] 71 5e [2] 77 6b [2] 59 6b [2] 66 77 }

  condition:
    any of them
}