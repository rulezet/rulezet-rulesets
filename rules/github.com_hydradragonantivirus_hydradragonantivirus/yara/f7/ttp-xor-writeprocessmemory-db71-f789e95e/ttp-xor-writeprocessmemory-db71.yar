rule TTP_XOR_WriteProcessMemory_db71 {
  strings:
    $key_db71 = { 8c 03 [2] be 21 [2] b8 14 [2] 96 14 [2] a9 08 }

  condition:
    any of them
}