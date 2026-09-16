rule TTP_XOR_WriteProcessMemory_36b3 {
  strings:
    $key_36b3 = { 61 c1 [2] 53 e3 [2] 55 d6 [2] 7b d6 [2] 44 ca }

  condition:
    any of them
}