rule TTP_XOR_WriteProcessMemory_325c {
  strings:
    $key_325c = { 65 2e [2] 57 0c [2] 51 39 [2] 7f 39 [2] 40 25 }

  condition:
    any of them
}