rule TTP_XOR_WriteProcessMemory_0e3c {
  strings:
    $key_0e3c = { 59 4e [2] 6b 6c [2] 6d 59 [2] 43 59 [2] 7c 45 }

  condition:
    any of them
}