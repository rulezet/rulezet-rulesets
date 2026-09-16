rule TTP_XOR_WriteProcessMemory_222c {
  strings:
    $key_222c = { 75 5e [2] 47 7c [2] 41 49 [2] 6f 49 [2] 50 55 }

  condition:
    any of them
}