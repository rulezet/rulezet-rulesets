rule TTP_XOR_WriteProcessMemory_a8bb {
  strings:
    $key_a8bb = { ff c9 [2] cd eb [2] cb de [2] e5 de [2] da c2 }

  condition:
    any of them
}