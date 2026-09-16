rule TTP_XOR_WriteProcessMemory_efc4 {
  strings:
    $key_efc4 = { b8 b6 [2] 8a 94 [2] 8c a1 [2] a2 a1 [2] 9d bd }

  condition:
    any of them
}