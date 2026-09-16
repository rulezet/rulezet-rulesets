rule TTP_XOR_WriteProcessMemory_68ee {
  strings:
    $key_68ee = { 3f 9c [2] 0d be [2] 0b 8b [2] 25 8b [2] 1a 97 }

  condition:
    any of them
}