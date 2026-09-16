rule TTP_XOR_WriteProcessMemory_5d3e {
  strings:
    $key_5d3e = { 0a 4c [2] 38 6e [2] 3e 5b [2] 10 5b [2] 2f 47 }

  condition:
    any of them
}