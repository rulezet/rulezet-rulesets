rule TTP_XOR_WriteProcessMemory_dc24 {
  strings:
    $key_dc24 = { 8b 56 [2] b9 74 [2] bf 41 [2] 91 41 [2] ae 5d }

  condition:
    any of them
}