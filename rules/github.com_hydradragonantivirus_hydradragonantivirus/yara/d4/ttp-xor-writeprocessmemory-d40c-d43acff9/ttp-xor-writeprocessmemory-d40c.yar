rule TTP_XOR_WriteProcessMemory_d40c {
  strings:
    $key_d40c = { 83 7e [2] b1 5c [2] b7 69 [2] 99 69 [2] a6 75 }

  condition:
    any of them
}