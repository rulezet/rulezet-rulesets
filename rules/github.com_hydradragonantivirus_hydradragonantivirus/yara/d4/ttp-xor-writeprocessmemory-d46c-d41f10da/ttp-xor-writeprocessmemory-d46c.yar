rule TTP_XOR_WriteProcessMemory_d46c {
  strings:
    $key_d46c = { 83 1e [2] b1 3c [2] b7 09 [2] 99 09 [2] a6 15 }

  condition:
    any of them
}