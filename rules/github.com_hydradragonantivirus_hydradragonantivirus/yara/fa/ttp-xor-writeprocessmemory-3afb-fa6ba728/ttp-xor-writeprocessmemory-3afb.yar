rule TTP_XOR_WriteProcessMemory_3afb {
  strings:
    $key_3afb = { 6d 89 [2] 5f ab [2] 59 9e [2] 77 9e [2] 48 82 }

  condition:
    any of them
}