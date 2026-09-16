rule TTP_XOR_WriteProcessMemory_144c {
  strings:
    $key_144c = { 43 3e [2] 71 1c [2] 77 29 [2] 59 29 [2] 66 35 }

  condition:
    any of them
}