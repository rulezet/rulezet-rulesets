rule TTP_XOR_WriteProcessMemory_372c {
  strings:
    $key_372c = { 60 5e [2] 52 7c [2] 54 49 [2] 7a 49 [2] 45 55 }

  condition:
    any of them
}