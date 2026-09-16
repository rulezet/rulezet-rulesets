rule TTP_XOR_WriteProcessMemory_efd7 {
  strings:
    $key_efd7 = { b8 a5 [2] 8a 87 [2] 8c b2 [2] a2 b2 [2] 9d ae }

  condition:
    any of them
}