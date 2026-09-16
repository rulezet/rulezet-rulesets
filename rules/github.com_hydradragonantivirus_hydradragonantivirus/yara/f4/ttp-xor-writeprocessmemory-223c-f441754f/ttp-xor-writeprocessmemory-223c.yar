rule TTP_XOR_WriteProcessMemory_223c {
  strings:
    $key_223c = { 75 4e [2] 47 6c [2] 41 59 [2] 6f 59 [2] 50 45 }

  condition:
    any of them
}