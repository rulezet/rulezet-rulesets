rule TTP_XOR_WriteProcessMemory_553c {
  strings:
    $key_553c = { 02 4e [2] 30 6c [2] 36 59 [2] 18 59 [2] 27 45 }

  condition:
    any of them
}