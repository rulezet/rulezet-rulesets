rule TTP_XOR_WriteProcessMemory_183c {
  strings:
    $key_183c = { 4f 4e [2] 7d 6c [2] 7b 59 [2] 55 59 [2] 6a 45 }

  condition:
    any of them
}