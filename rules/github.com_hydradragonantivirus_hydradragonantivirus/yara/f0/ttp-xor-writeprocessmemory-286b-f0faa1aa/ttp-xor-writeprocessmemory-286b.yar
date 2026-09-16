rule TTP_XOR_WriteProcessMemory_286b {
  strings:
    $key_286b = { 7f 19 [2] 4d 3b [2] 4b 0e [2] 65 0e [2] 5a 12 }

  condition:
    any of them
}