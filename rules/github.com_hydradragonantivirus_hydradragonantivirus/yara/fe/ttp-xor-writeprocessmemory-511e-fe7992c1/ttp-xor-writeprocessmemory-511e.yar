rule TTP_XOR_WriteProcessMemory_511e {
  strings:
    $key_511e = { 06 6c [2] 34 4e [2] 32 7b [2] 1c 7b [2] 23 67 }

  condition:
    any of them
}