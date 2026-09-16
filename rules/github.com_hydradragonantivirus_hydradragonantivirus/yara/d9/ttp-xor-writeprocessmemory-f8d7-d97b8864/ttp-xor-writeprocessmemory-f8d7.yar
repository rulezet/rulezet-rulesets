rule TTP_XOR_WriteProcessMemory_f8d7 {
  strings:
    $key_f8d7 = { af a5 [2] 9d 87 [2] 9b b2 [2] b5 b2 [2] 8a ae }

  condition:
    any of them
}