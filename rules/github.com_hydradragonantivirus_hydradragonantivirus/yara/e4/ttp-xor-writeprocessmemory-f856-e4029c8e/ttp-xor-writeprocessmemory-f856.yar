rule TTP_XOR_WriteProcessMemory_f856 {
  strings:
    $key_f856 = { af 24 [2] 9d 06 [2] 9b 33 [2] b5 33 [2] 8a 2f }

  condition:
    any of them
}