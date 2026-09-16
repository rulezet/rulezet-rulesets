rule TTP_XOR_WriteProcessMemory_5bc3 {
  strings:
    $key_5bc3 = { 0c b1 [2] 3e 93 [2] 38 a6 [2] 16 a6 [2] 29 ba }

  condition:
    any of them
}