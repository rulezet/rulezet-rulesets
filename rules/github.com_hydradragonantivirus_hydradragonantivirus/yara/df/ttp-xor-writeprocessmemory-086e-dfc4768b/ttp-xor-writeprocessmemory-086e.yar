rule TTP_XOR_WriteProcessMemory_086e {
  strings:
    $key_086e = { 5f 1c [2] 6d 3e [2] 6b 0b [2] 45 0b [2] 7a 17 }

  condition:
    any of them
}