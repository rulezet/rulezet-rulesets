rule TTP_XOR_WriteProcessMemory_6cee {
  strings:
    $key_6cee = { 3b 9c [2] 09 be [2] 0f 8b [2] 21 8b [2] 1e 97 }

  condition:
    any of them
}