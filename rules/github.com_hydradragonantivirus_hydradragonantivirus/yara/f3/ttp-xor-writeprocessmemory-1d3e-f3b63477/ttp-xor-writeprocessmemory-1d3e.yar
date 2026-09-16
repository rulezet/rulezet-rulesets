rule TTP_XOR_WriteProcessMemory_1d3e {
  strings:
    $key_1d3e = { 4a 4c [2] 78 6e [2] 7e 5b [2] 50 5b [2] 6f 47 }

  condition:
    any of them
}