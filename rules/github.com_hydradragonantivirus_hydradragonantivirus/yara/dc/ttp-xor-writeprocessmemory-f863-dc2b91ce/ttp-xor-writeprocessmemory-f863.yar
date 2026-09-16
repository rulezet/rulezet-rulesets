rule TTP_XOR_WriteProcessMemory_f863 {
  strings:
    $key_f863 = { af 11 [2] 9d 33 [2] 9b 06 [2] b5 06 [2] 8a 1a }

  condition:
    any of them
}