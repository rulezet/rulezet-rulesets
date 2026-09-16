rule TTP_XOR_WriteProcessMemory_785c {
  strings:
    $key_785c = { 2f 2e [2] 1d 0c [2] 1b 39 [2] 35 39 [2] 0a 25 }

  condition:
    any of them
}