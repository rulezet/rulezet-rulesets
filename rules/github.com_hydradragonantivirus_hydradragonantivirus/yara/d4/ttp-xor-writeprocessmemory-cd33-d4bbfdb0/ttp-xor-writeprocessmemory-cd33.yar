rule TTP_XOR_WriteProcessMemory_cd33 {
  strings:
    $key_cd33 = { 9a 41 [2] a8 63 [2] ae 56 [2] 80 56 [2] bf 4a }

  condition:
    any of them
}