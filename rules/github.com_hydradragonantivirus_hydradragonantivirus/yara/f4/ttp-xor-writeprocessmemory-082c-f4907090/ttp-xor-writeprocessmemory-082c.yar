rule TTP_XOR_WriteProcessMemory_082c {
  strings:
    $key_082c = { 5f 5e [2] 6d 7c [2] 6b 49 [2] 45 49 [2] 7a 55 }

  condition:
    any of them
}