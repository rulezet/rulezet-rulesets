rule TTP_XOR_WriteProcessMemory_753e {
  strings:
    $key_753e = { 22 4c [2] 10 6e [2] 16 5b [2] 38 5b [2] 07 47 }

  condition:
    any of them
}