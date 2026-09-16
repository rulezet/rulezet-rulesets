rule TTP_XOR_WriteProcessMemory_0eee {
  strings:
    $key_0eee = { 59 9c [2] 6b be [2] 6d 8b [2] 43 8b [2] 7c 97 }

  condition:
    any of them
}