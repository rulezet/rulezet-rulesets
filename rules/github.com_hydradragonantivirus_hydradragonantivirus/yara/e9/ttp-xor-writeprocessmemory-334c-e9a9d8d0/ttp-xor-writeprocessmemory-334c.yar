rule TTP_XOR_WriteProcessMemory_334c {
  strings:
    $key_334c = { 64 3e [2] 56 1c [2] 50 29 [2] 7e 29 [2] 41 35 }

  condition:
    any of them
}