rule TTP_XOR_WriteProcessMemory_db54 {
  strings:
    $key_db54 = { 8c 26 [2] be 04 [2] b8 31 [2] 96 31 [2] a9 2d }

  condition:
    any of them
}