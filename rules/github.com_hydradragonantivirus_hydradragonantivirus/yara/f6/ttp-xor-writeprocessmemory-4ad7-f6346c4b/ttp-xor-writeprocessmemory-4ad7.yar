rule TTP_XOR_WriteProcessMemory_4ad7 {
  strings:
    $key_4ad7 = { 1d a5 [2] 2f 87 [2] 29 b2 [2] 07 b2 [2] 38 ae }

  condition:
    any of them
}