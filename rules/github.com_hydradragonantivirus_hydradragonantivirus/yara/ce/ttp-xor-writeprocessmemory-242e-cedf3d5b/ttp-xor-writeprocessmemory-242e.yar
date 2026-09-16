rule TTP_XOR_WriteProcessMemory_242e {
  strings:
    $key_242e = { 73 5c [2] 41 7e [2] 47 4b [2] 69 4b [2] 56 57 }

  condition:
    any of them
}