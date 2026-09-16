rule TTP_XOR_WriteProcessMemory_db1c {
  strings:
    $key_db1c = { 8c 6e [2] be 4c [2] b8 79 [2] 96 79 [2] a9 65 }

  condition:
    any of them
}