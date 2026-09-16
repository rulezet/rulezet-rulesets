rule TTP_XOR_WriteProcessMemory_eeee {
  strings:
    $key_eeee = { b9 9c [2] 8b be [2] 8d 8b [2] a3 8b [2] 9c 97 }

  condition:
    any of them
}