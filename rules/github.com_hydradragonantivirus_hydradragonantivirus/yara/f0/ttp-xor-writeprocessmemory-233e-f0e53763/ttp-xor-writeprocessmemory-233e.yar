rule TTP_XOR_WriteProcessMemory_233e {
  strings:
    $key_233e = { 74 4c [2] 46 6e [2] 40 5b [2] 6e 5b [2] 51 47 }

  condition:
    any of them
}