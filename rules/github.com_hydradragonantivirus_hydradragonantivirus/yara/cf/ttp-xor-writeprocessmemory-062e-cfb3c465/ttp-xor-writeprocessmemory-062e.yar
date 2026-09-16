rule TTP_XOR_WriteProcessMemory_062e {
  strings:
    $key_062e = { 51 5c [2] 63 7e [2] 65 4b [2] 4b 4b [2] 74 57 }

  condition:
    any of them
}