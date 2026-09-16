rule TTP_XOR_WriteProcessMemory_193c {
  strings:
    $key_193c = { 4e 4e [2] 7c 6c [2] 7a 59 [2] 54 59 [2] 6b 45 }

  condition:
    any of them
}