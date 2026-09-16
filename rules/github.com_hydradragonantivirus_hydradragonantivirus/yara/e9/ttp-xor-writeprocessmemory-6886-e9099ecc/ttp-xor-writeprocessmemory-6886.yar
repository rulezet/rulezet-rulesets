rule TTP_XOR_WriteProcessMemory_6886 {
  strings:
    $key_6886 = { 3f f4 [2] 0d d6 [2] 0b e3 [2] 25 e3 [2] 1a ff }

  condition:
    any of them
}