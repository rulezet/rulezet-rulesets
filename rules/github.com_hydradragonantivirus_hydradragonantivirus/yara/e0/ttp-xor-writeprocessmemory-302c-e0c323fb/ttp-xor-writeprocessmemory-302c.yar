rule TTP_XOR_WriteProcessMemory_302c {
  strings:
    $key_302c = { 67 5e [2] 55 7c [2] 53 49 [2] 7d 49 [2] 42 55 }

  condition:
    any of them
}