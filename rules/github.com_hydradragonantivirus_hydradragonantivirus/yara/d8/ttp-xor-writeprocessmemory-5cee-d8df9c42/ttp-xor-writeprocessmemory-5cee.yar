rule TTP_XOR_WriteProcessMemory_5cee {
  strings:
    $key_5cee = { 0b 9c [2] 39 be [2] 3f 8b [2] 11 8b [2] 2e 97 }

  condition:
    any of them
}