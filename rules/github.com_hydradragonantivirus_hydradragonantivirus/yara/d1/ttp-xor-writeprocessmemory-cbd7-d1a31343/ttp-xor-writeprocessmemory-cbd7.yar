rule TTP_XOR_WriteProcessMemory_cbd7 {
  strings:
    $key_cbd7 = { 9c a5 [2] ae 87 [2] a8 b2 [2] 86 b2 [2] b9 ae }

  condition:
    any of them
}