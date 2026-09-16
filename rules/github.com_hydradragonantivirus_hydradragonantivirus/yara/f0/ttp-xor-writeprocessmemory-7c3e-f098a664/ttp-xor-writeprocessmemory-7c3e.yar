rule TTP_XOR_WriteProcessMemory_7c3e {
  strings:
    $key_7c3e = { 2b 4c [2] 19 6e [2] 1f 5b [2] 31 5b [2] 0e 47 }

  condition:
    any of them
}