rule TTP_XOR_WriteProcessMemory_043c {
  strings:
    $key_043c = { 53 4e [2] 61 6c [2] 67 59 [2] 49 59 [2] 76 45 }

  condition:
    any of them
}