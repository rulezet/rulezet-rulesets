rule TTP_XOR_WriteProcessMemory_126c {
  strings:
    $key_126c = { 45 1e [2] 77 3c [2] 71 09 [2] 5f 09 [2] 60 15 }

  condition:
    any of them
}