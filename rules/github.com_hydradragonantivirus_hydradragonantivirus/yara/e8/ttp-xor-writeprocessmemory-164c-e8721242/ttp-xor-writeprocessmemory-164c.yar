rule TTP_XOR_WriteProcessMemory_164c {
  strings:
    $key_164c = { 41 3e [2] 73 1c [2] 75 29 [2] 5b 29 [2] 64 35 }

  condition:
    any of them
}