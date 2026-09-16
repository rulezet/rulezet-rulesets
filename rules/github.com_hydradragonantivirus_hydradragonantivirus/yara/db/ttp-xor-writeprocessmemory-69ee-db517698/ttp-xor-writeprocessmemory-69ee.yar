rule TTP_XOR_WriteProcessMemory_69ee {
  strings:
    $key_69ee = { 3e 9c [2] 0c be [2] 0a 8b [2] 24 8b [2] 1b 97 }

  condition:
    any of them
}