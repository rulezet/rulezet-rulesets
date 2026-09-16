rule TTP_XOR_WriteProcessMemory_2886 {
  strings:
    $key_2886 = { 7f f4 [2] 4d d6 [2] 4b e3 [2] 65 e3 [2] 5a ff }

  condition:
    any of them
}