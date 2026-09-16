rule TTP_XOR_WriteProcessMemory_db47 {
  strings:
    $key_db47 = { 8c 35 [2] be 17 [2] b8 22 [2] 96 22 [2] a9 3e }

  condition:
    any of them
}