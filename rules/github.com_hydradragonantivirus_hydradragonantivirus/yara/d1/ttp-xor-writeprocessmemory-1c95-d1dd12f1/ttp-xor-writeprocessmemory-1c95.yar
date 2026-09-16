rule TTP_XOR_WriteProcessMemory_1c95 {
  strings:
    $key_1c95 = { 4b e7 [2] 79 c5 [2] 7f f0 [2] 51 f0 [2] 6e ec }

  condition:
    any of them
}