rule TTP_XOR_WriteProcessMemory_fec3 {
  strings:
    $key_fec3 = { a9 b1 [2] 9b 93 [2] 9d a6 [2] b3 a6 [2] 8c ba }

  condition:
    any of them
}