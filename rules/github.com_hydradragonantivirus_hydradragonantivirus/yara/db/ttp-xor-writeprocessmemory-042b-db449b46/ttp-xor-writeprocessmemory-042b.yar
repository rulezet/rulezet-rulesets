rule TTP_XOR_WriteProcessMemory_042b {
  strings:
    $key_042b = { 53 59 [2] 61 7b [2] 67 4e [2] 49 4e [2] 76 52 }

  condition:
    any of them
}