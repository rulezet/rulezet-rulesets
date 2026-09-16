rule TTP_XOR_WriteProcessMemory_7cee {
  strings:
    $key_7cee = { 2b 9c [2] 19 be [2] 1f 8b [2] 31 8b [2] 0e 97 }

  condition:
    any of them
}