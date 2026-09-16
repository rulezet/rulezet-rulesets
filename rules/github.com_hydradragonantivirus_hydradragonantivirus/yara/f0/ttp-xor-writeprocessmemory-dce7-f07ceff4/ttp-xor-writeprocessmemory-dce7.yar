rule TTP_XOR_WriteProcessMemory_dce7 {
  strings:
    $key_dce7 = { 8b 95 [2] b9 b7 [2] bf 82 [2] 91 82 [2] ae 9e }

  condition:
    any of them
}