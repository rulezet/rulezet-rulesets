rule TTP_XOR_WriteProcessMemory_51ee {
  strings:
    $key_51ee = { 06 9c [2] 34 be [2] 32 8b [2] 1c 8b [2] 23 97 }

  condition:
    any of them
}