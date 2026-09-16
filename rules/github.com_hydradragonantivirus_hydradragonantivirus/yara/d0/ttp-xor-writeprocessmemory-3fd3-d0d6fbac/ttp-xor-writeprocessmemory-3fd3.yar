rule TTP_XOR_WriteProcessMemory_3fd3 {
  strings:
    $key_3fd3 = { 68 a1 [2] 5a 83 [2] 5c b6 [2] 72 b6 [2] 4d aa }

  condition:
    any of them
}