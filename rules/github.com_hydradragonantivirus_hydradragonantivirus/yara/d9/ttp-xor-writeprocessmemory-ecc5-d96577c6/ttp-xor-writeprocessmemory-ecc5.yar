rule TTP_XOR_WriteProcessMemory_ecc5 {
  strings:
    $key_ecc5 = { bb b7 [2] 89 95 [2] 8f a0 [2] a1 a0 [2] 9e bc }

  condition:
    any of them
}