rule TTP_XOR_WriteProcessMemory_0cc6 {
  strings:
    $key_0cc6 = { 5b b4 [2] 69 96 [2] 6f a3 [2] 41 a3 [2] 7e bf }

  condition:
    any of them
}