rule TTP_XOR_WriteProcessMemory_c10c {
  strings:
    $key_c10c = { 96 7e [2] a4 5c [2] a2 69 [2] 8c 69 [2] b3 75 }

  condition:
    any of them
}