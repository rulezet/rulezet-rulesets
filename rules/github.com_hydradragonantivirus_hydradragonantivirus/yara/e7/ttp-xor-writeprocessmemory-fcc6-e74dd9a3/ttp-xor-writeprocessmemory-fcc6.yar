rule TTP_XOR_WriteProcessMemory_fcc6 {
  strings:
    $key_fcc6 = { ab b4 [2] 99 96 [2] 9f a3 [2] b1 a3 [2] 8e bf }

  condition:
    any of them
}