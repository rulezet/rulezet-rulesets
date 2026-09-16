rule TTP_XOR_WriteProcessMemory_282c {
  strings:
    $key_282c = { 7f 5e [2] 4d 7c [2] 4b 49 [2] 65 49 [2] 5a 55 }

  condition:
    any of them
}