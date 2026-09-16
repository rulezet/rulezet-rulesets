rule TTP_XOR_WriteProcessMemory_22ee {
  strings:
    $key_22ee = { 75 9c [2] 47 be [2] 41 8b [2] 6f 8b [2] 50 97 }

  condition:
    any of them
}