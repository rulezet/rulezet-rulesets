rule TTP_XOR_WriteProcessMemory_2c95 {
  strings:
    $key_2c95 = { 7b e7 [2] 49 c5 [2] 4f f0 [2] 61 f0 [2] 5e ec }

  condition:
    any of them
}