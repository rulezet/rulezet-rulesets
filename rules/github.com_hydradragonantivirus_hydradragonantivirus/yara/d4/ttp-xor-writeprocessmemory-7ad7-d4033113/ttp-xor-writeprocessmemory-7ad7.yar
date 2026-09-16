rule TTP_XOR_WriteProcessMemory_7ad7 {
  strings:
    $key_7ad7 = { 2d a5 [2] 1f 87 [2] 19 b2 [2] 37 b2 [2] 08 ae }

  condition:
    any of them
}