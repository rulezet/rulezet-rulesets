rule TTP_XOR_WriteProcessMemory_2d3c {
  strings:
    $key_2d3c = { 7a 4e [2] 48 6c [2] 4e 59 [2] 60 59 [2] 5f 45 }

  condition:
    any of them
}