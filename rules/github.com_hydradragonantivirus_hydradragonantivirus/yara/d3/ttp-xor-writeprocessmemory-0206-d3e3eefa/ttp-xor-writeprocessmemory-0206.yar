rule TTP_XOR_WriteProcessMemory_0206 {
  strings:
    $key_0206 = { 55 74 [2] 67 56 [2] 61 63 [2] 4f 63 [2] 70 7f }

  condition:
    any of them
}