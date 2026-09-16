rule TTP_XOR_WriteProcessMemory_745c {
  strings:
    $key_745c = { 23 2e [2] 11 0c [2] 17 39 [2] 39 39 [2] 06 25 }

  condition:
    any of them
}