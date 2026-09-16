rule TTP_XOR_WriteProcessMemory_243c {
  strings:
    $key_243c = { 73 4e [2] 41 6c [2] 47 59 [2] 69 59 [2] 56 45 }

  condition:
    any of them
}