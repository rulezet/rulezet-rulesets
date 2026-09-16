rule TTP_XOR_WriteProcessMemory_ecc6 {
  strings:
    $key_ecc6 = { bb b4 [2] 89 96 [2] 8f a3 [2] a1 a3 [2] 9e bf }

  condition:
    any of them
}