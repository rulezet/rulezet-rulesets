rule TTP_XOR_WriteProcessMemory_26c6 {
  strings:
    $key_26c6 = { 71 b4 [2] 43 96 [2] 45 a3 [2] 6b a3 [2] 54 bf }

  condition:
    any of them
}