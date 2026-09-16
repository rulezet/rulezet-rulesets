rule TTP_XOR_WriteProcessMemory_cde4 {
  strings:
    $key_cde4 = { 9a 96 [2] a8 b4 [2] ae 81 [2] 80 81 [2] bf 9d }

  condition:
    any of them
}