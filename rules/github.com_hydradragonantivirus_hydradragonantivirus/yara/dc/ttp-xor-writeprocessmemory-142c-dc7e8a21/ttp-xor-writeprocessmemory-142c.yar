rule TTP_XOR_WriteProcessMemory_142c {
  strings:
    $key_142c = { 43 5e [2] 71 7c [2] 77 49 [2] 59 49 [2] 66 55 }

  condition:
    any of them
}