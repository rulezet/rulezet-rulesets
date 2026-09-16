rule TTP_XOR_WriteProcessMemory_73ee {
  strings:
    $key_73ee = { 24 9c [2] 16 be [2] 10 8b [2] 3e 8b [2] 01 97 }

  condition:
    any of them
}