rule TTP_XOR_WriteProcessMemory_311e {
  strings:
    $key_311e = { 66 6c [2] 54 4e [2] 52 7b [2] 7c 7b [2] 43 67 }

  condition:
    any of them
}