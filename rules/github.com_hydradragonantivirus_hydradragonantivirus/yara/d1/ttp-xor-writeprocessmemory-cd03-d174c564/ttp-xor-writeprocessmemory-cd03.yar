rule TTP_XOR_WriteProcessMemory_cd03 {
  strings:
    $key_cd03 = { 9a 71 [2] a8 53 [2] ae 66 [2] 80 66 [2] bf 7a }

  condition:
    any of them
}