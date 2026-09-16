rule TTP_XOR_WriteProcessMemory_71ee {
  strings:
    $key_71ee = { 26 9c [2] 14 be [2] 12 8b [2] 3c 8b [2] 03 97 }

  condition:
    any of them
}