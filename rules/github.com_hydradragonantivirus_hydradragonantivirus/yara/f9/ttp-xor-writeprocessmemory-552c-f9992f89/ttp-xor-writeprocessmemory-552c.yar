rule TTP_XOR_WriteProcessMemory_552c {
  strings:
    $key_552c = { 02 5e [2] 30 7c [2] 36 49 [2] 18 49 [2] 27 55 }

  condition:
    any of them
}