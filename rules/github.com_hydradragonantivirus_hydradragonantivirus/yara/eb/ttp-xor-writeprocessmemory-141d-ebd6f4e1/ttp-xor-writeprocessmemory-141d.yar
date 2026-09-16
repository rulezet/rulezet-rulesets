rule TTP_XOR_WriteProcessMemory_141d {
  strings:
    $key_141d = { 43 6f [2] 71 4d [2] 77 78 [2] 59 78 [2] 66 64 }

  condition:
    any of them
}