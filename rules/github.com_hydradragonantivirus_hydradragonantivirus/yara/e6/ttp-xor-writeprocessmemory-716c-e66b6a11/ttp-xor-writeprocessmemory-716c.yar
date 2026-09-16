rule TTP_XOR_WriteProcessMemory_716c {
  strings:
    $key_716c = { 26 1e [2] 14 3c [2] 12 09 [2] 3c 09 [2] 03 15 }

  condition:
    any of them
}