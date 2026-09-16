rule TTP_XOR_WriteProcessMemory_1aee {
  strings:
    $key_1aee = { 4d 9c [2] 7f be [2] 79 8b [2] 57 8b [2] 68 97 }

  condition:
    any of them
}