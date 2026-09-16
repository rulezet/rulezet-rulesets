rule TTP_XOR_WriteProcessMemory_333c {
  strings:
    $key_333c = { 64 4e [2] 56 6c [2] 50 59 [2] 7e 59 [2] 41 45 }

  condition:
    any of them
}