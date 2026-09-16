rule TTP_XOR_WriteProcessMemory_33ee {
  strings:
    $key_33ee = { 64 9c [2] 56 be [2] 50 8b [2] 7e 8b [2] 41 97 }

  condition:
    any of them
}